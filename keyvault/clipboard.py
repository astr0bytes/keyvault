"""Copy text to the system clipboard using whatever tool is available."""

import os
import shutil
import subprocess

COMMANDS = [
    ["wl-copy"],
    ["xclip", "-selection", "clipboard"],
    ["xsel", "--clipboard", "--input"],
    ["pbcopy"],
]


class ClipboardError(Exception):
    pass


def _candidates():
    for cmd in COMMANDS:
        # wl-copy only works inside a Wayland session
        if cmd[0] == "wl-copy" and not os.environ.get("WAYLAND_DISPLAY"):
            continue
        if shutil.which(cmd[0]):
            yield cmd


def copy(text: str) -> str:
    """Copy text and return the name of the tool that was used."""
    for cmd in _candidates():
        try:
            subprocess.run(cmd, input=text.encode(), check=True, timeout=5)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue
        return cmd[0]
    raise ClipboardError("no clipboard tool found (install wl-clipboard, xclip or xsel)")
