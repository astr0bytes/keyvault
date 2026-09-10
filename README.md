# keyvault

Small command line secret store for API keys, tokens and passwords. Secrets are kept
in a single file encrypted with Fernet, using a key derived from a master password
with scrypt.

## Install

```
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```
python main.py init
python main.py add GITHUB_TOKEN -t github
python main.py list
python main.py get GITHUB_TOKEN
python main.py get GITHUB_TOKEN --clip
python main.py rename GITHUB_TOKEN GH_TOKEN
python main.py export -t github -o .env
python main.py gen -l 32
python main.py gen --token
```

If the value is omitted, `add` prompts for it so it does not end up in your shell history.

`get --clip` needs `wl-copy` (Wayland), `xclip` or `xsel` on Linux, and uses `pbcopy` on macOS.

The vault is stored in `~/.keyvault/vault.json` by default. Use `--vault PATH` to
work with another file.

## Tests

```
python -m unittest
```
