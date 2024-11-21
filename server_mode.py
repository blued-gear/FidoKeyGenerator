import datetime
import os
import signal
import socket
import stat
import sys

from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice
from fido2.webauthn import (PublicKeyCredentialRequestOptions,
                            PublicKeyCredentialType,
                            PublicKeyCredentialDescriptor)

from utils import *

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

class ServerMode:

    def __init__(self, dev: CtapHidDevice | CtapPcscDevice, path: str, use_cache: bool, cred_id_str: str):
        cred_id_parts = cred_id_str.split(":")
        if len(cred_id_parts) != 2:
            eprint("invalid ID param")
            sys.exit(1)
        self.rp_id = bytes.fromhex(cred_id_parts[0]).decode("utf-8")
        self.cred_id = bytes.fromhex(cred_id_parts[1])

        self.path = path
        self.exiting = False

        self.fido_client: Fido2Client = Fido2Client(dev, f"https://{self.rp_id}", user_interaction=CliInteraction())
        self.server: socket.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.key_cache: dict[str, bytes] | None = None

        if use_cache:
            self.key_cache = {}
        self.server.bind(path)


    def run_server(self):
        def cleanup(_, __):
            self.cleanup()
        signal.signal(signal.SIGINT, cleanup)
        signal.signal(signal.SIGTERM, cleanup)
        signal.signal(signal.SIGHUP, cleanup)

        print("running server at " + self.path)
        self.server.listen(1)

        try:
            while True:
                conn, client_address = self.server.accept()
                self._handle_connection(conn)
        except Exception as e:
            if not self.exiting:
                raise e


    def _handle_connection(self, client: socket.socket):
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " handling request")

        try:
            inp = ""
            while True:
                data = client.recv(1024)
                if not data:
                    break
                inp += data.decode("utf-8")

            outp: bytes | None = None
            if self.key_cache is not None:
                outp = self.key_cache.get(inp)
            if outp is None:
                outp = self._read_key(inp)

            client.sendall(outp)
        except Exception as e:
            eprint("error while handling request")
            eprint(e)
        finally:
            client.close()


    def _read_key(self, inp: str) -> bytes:
        challenge = secrets.token_bytes(16)
        allow_list = [PublicKeyCredentialDescriptor(type=PublicKeyCredentialType("public-key"), id=self.cred_id)]
        data = hashlib.sha256(inp.encode("utf-8")).digest()

        result = self.fido_client.get_assertion(PublicKeyCredentialRequestOptions(
            rp_id=self.rp_id,
            challenge=challenge,
            allow_credentials=allow_list,
            extensions={"hmacGetSecret": {"salt1": data}},
        )).get_response(0)  # Only one cred in allowList, only one response.

        output = result.extension_results["hmacGetSecret"]["output1"]
        ret: bytes = output.hex().encode("utf-8")

        if self.key_cache is not None:
            self.key_cache[inp] = ret

        return ret

    def cleanup(self):
        print("exiting")
        self.exiting = True

        self.server.shutdown(socket.SHUT_RDWR)
        self.server.close()

        if stat.S_ISSOCK(os.stat(self.path).st_mode):
            os.remove(self.path)
