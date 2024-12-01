# FidoKeyGenerator

With this small application it is possible to use any FIDO2 authenticator, 
which supports the *HMAC-Secret* extension, to generate as many symmetric cryptographic keys
as you want.

The output depends on the used credential (created once) and an input string.\
The secret will be derived from the input by the authenticator
(so the same input + credential will always result in the same key).

# Usage
## Installation

```shell
# clone and ce into the repo
python -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
```

## Use it

Preparation to use the script from any location:
```shell
KEYGEN_DIR="<path to repo>"
source $KEYGEN_DIR/venv/bin/activate
```

Firstly, a credential has to be created:
```shell
CREDENTIAL=$(python "$KEYGEN_DIR/fidokeygenerator.py" --init "Example@my.scope")
echo $CREDENTIAL
```

Now you can derive keys from any input:
```shell
echo 'some input to digest' | python3 "$KEYGEN_DIR/fidokeygenerator.py" "$CREDENTIAL"
```

\
To see all options run
`python3 fidokeygenerator.py --help`

### Server Mode

In this mode the application will create a Unix-socket and listens for connections, 
which provide the input to digest.\
By using `--cache` the generated secrets will be cached so you don't have to interact with your authenticator after the initial request
(except when a unencountered input is sent).

```shell
python3 "$KEYGEN_DIR/fidokeygenerator.py"  --server "<path for the .sock file>" --cache "$CREDENTIAL"
```

## Examples

Some example are shown in my Blog:
[Extra factor for Monero Wallet](https://projects.chocolatecakecodes.goip.de/blued_gear/blog/-/wikis/Script:-use-FidoKeyGenerator-for-2FA-of-Monero-GUI),
[Key for Bormatic](https://projects.chocolatecakecodes.goip.de/blued_gear/blog/-/wikis/Use-FIDO-Key-for-Borgmatic).

# Acknowledgements

Most of the code was taken from [python-fido2 hmac_secret example](https://github.com/Yubico/python-fido2/blob/main/examples/hmac_secret.py).

# License

MIT
