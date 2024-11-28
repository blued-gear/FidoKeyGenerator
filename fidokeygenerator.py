# code inspired from https://github.com/Yubico/python-fido2/blob/main/examples/hmac_secret.py

import argparse
import hashlib
import secrets

from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice
from fido2.webauthn import (PublicKeyCredentialCreationOptions,
                            PublicKeyCredentialRequestOptions,
                            PublicKeyCredentialRpEntity,
                            PublicKeyCredentialUserEntity,
                            PublicKeyCredentialParameters,
                            PublicKeyCredentialType,
                            PublicKeyCredentialDescriptor)

from server_mode import ServerMode
from utils import *

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None


def enumerate_usable_devices():
    for dev in CtapHidDevice.list_devices():
        client = Fido2Client(dev, "")
        if "hmac-secret" in client.info.extensions:
            yield dev

    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            client = Fido2Client(dev, "")
            if "hmac-secret" in client.info.extensions:
                yield dev


def find_device(path: str = None):
    devices = enumerate_usable_devices()
    first = None
    count = 0

    for dev in devices:
        count += 1
        if first is None:
            first = dev

        if path is not None:
            if dev.descriptor.path == path:
                return dev

    if path is not None:
        eprint("Specified device was not found.")
        sys.exit(2)
    if count == 0:
        eprint("No suitable device was found.")
        sys.exit(2)
    if count > 1:
        eprint("More than one device was found. Specify one with -d")
        sys.exit(2)

    return first


def list_devices():
    devices = enumerate_usable_devices()
    for dev in devices:
        print(f"{dev.product_name} : {dev.descriptor.path}")


def init_cred(dev: CtapHidDevice | CtapPcscDevice, user: str, domain: str):
    user_hash = hashlib.sha256(user.encode("utf-8")).digest()
    user = PublicKeyCredentialUserEntity(id=user_hash, name=user)
    rp = PublicKeyCredentialRpEntity(id=domain, name=domain)
    challenge = secrets.token_bytes(16)

    client = Fido2Client(dev, f"https://{domain}", user_interaction=CliInteraction())

    result = client.make_credential(PublicKeyCredentialCreationOptions(
        rp=rp,
        user=user,
        challenge=challenge,
        pub_key_cred_params=[PublicKeyCredentialParameters(
            type=PublicKeyCredentialType("public-key"),
            alg=-7  # ES256
        )],
        extensions={"hmacCreateSecret": True},
    ))

    cred = result.attestation_object.auth_data.credential_data
    cred_id = cred.credential_id

    print("Credential ID:")
    print(f"{domain.encode("utf-8").hex()}:{cred_id.hex()}")

    if not result.extension_results.get("hmacCreateSecret"):
        eprint("Could not create a credential with HMAC-Secret")
        sys.exit(3)


def process_secret(dev: CtapHidDevice | CtapPcscDevice, cred_id_str: str):
    cred_id_parts = cred_id_str.split(":")
    if len(cred_id_parts) != 2:
        eprint("invalid ID param")
        sys.exit(1)
    rp_id = bytes.fromhex(cred_id_parts[0]).decode("utf-8")
    cred_id = bytes.fromhex(cred_id_parts[1])

    client = Fido2Client(dev, f"https://{rp_id}", user_interaction=CliInteraction())

    challenge = secrets.token_bytes(16)
    allow_list = [PublicKeyCredentialDescriptor(type=PublicKeyCredentialType("public-key"), id=cred_id)]
    data = hashlib.sha256(read_full_stdin()).digest()

    result = client.get_assertion(PublicKeyCredentialRequestOptions(
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=allow_list,
        extensions={"hmacGetSecret": {"salt1": data}},
    )).get_response(0)  # Only one cred in allowList, only one response.

    output = result.extension_results["hmacGetSecret"]["output1"]
    print(output.hex())


def process_args():
    parser = argparse.ArgumentParser(
        description="FidoKeyGenerator: generate static keys with your FIDO2 Key. The input is read from stdin and the secret is output as Hex to stdout."
    )
    parser.add_argument(
        "--list",
        default=False,
        action="store_true",
        help="list all supported devices and exit"
    )
    parser.add_argument(
        "--device", "-d",
        type=str,
        default=None,
        help="explicit specify device-path to use (list available paths with --list) (if omitted autoselects if only one suitable is available)"
    )
    parser.add_argument(
        "--init",
        default=False,
        action="store_true",
        help="Init a new credential. 'param' must be given in the form of <Some string>@<some.string>"
    )
    parser.add_argument(
        "--server",
        type=str,
        default=False,
        metavar="PATH",
        help="run in server-mode: create a unix-socket at the given path, read input for each connection and output the key (as hex)"
    )
    parser.add_argument(
        "--cache",
        default=False,
        action="store_true",
        help="[only for --server] if input is encoutered twice the output will be returned without triggering the FIDO-key"
    )
    parser.add_argument(
        "param",
        type=str,
        nargs="?",
        default="",
        help="in normal mode: the ID of the credential (generated with --init) ; in init mode: <Some string>@<some.string>"
    )

    return parser.parse_args()


def main():
    args = process_args()

    if args.list:
        list_devices()
        return

    dev = find_device(args.device)

    if args.init:
        user_param = args.param
        if len(user_param) == 0:
            eprint("expected user for param")
            sys.exit(1)

        split = user_param.split("@")
        if len(split) != 2:
            eprint("wrong format for init param")
            sys.exit(1)
        if " " in split[1]:
            eprint("wrong format for init param")
            sys.exit(1)

        init_cred(dev, split[0], split[1])
    elif args.server is not None and args.server != False:
        id_param = args.param
        if len(id_param) == 0:
            eprint("expected ID for param")
            sys.exit(1)
        server = ServerMode(dev, args.server, args.cache, id_param)

        try:
            server.run_server()
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        id_param = args.param
        if len(id_param) == 0:
            eprint("expected ID for param")
            sys.exit(1)

        process_secret(dev, id_param)


main()
