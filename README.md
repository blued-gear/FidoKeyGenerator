# FidoKeyGenerator

With this small app it is possible to use any FIDO2 authenticator, 
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
`python fidokeygenerator.py --help`

# Acknowledgements

Most of the code was taken from [python-fido2 hmac_secret example](https://github.com/Yubico/python-fido2/blob/main/examples/hmac_secret.py).

# License

MIT
