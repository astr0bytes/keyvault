#!/usr/bin/env python3
"""keyvault - local encrypted secret store for developers."""

import argparse
import getpass
import sys
from pathlib import Path

from keyvault import __version__
from keyvault.crypto import InvalidPassword
from keyvault.generator import generate_password, generate_token
from keyvault.storage import DEFAULT_VAULT_PATH, Vault, VaultError


def ask_password(confirm: bool = False) -> str:
    password = getpass.getpass("Master password: ")
    if confirm and password != getpass.getpass("Confirm: "):
        sys.exit("Passwords do not match.")
    if not password:
        sys.exit("Empty password not allowed.")
    return password


def cmd_init(args):
    Vault.create(args.vault, ask_password(confirm=True))
    print(f"Vault created: {args.vault}")


def cmd_add(args):
    vault = Vault.open(args.vault, ask_password())
    value = args.value or getpass.getpass(f"Value for {args.name}: ")
    vault.set(args.name, value, tags=args.tag or [])
    vault.save()
    print(f"Secret '{args.name}' saved.")


def cmd_get(args):
    vault = Vault.open(args.vault, ask_password())
    print(vault.get(args.name))


def cmd_list(args):
    vault = Vault.open(args.vault, ask_password())
    for name, entry in sorted(vault.entries(tag=args.tag).items()):
        tags = ",".join(entry["tags"])
        print(f"{name:30} {entry['updated']:25} {tags}")


def cmd_delete(args):
    vault = Vault.open(args.vault, ask_password())
    vault.delete(args.name)
    vault.save()
    print(f"Secret '{args.name}' deleted.")


def cmd_export(args):
    vault = Vault.open(args.vault, ask_password())
    lines = [f'{name}="{entry["value"]}"' for name, entry in sorted(vault.entries(tag=args.tag).items())]
    content = "\n".join(lines) + "\n"
    if args.output:
        Path(args.output).write_text(content)
        Path(args.output).chmod(0o600)
        print(f"Exported {len(lines)} secret(s) to {args.output}")
    else:
        sys.stdout.write(content)


def cmd_gen(args):
    if args.token:
        print(generate_token(args.length))
    else:
        print(generate_password(args.length, symbols=not args.no_symbols))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keyvault", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT_PATH, help="path to the vault file")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)

    p = sub.add_parser("add", help="add or update a secret")
    p.add_argument("name")
    p.add_argument("value", nargs="?", help="secret value (prompted if omitted)")
    p.add_argument("-t", "--tag", action="append", help="tag (can be repeated)")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("get", help="print a secret")
    p.add_argument("name")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("list", help="list secrets")
    p.add_argument("-t", "--tag")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("delete", help="delete a secret")
    p.add_argument("name")
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("export", help="export secrets as a .env file")
    p.add_argument("-t", "--tag")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("gen", help="generate a password or a token")
    p.add_argument("-l", "--length", type=int, default=24)
    p.add_argument("--token", action="store_true", help="URL-safe token")
    p.add_argument("--no-symbols", action="store_true")
    p.set_defaults(func=cmd_gen)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except InvalidPassword:
        print("Wrong password.", file=sys.stderr)
        return 1
    except VaultError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
