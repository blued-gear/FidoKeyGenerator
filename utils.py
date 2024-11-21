import os
import sys
from getpass import getpass

from fido2.client import UserInteraction


def eprint(msg):
    print(msg, file=sys.stderr)


def read_full_stdin() -> bytes:
    stdin = os.fdopen(os.dup(sys.stdin.fileno()), 'rb')
    if sys.platform.startswith('win'):
        try:
            __import__('msvcrt').setmode(stdin.fileno(), os.O_BINARY)
        except ImportError:
            pass

    return stdin.read()


class CliInteraction(UserInteraction):
    def prompt_up(self):
        eprint("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        eprint("User Verification required.")
        return True
