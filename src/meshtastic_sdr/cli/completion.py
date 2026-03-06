"""Shell completion setup subcommand."""

import sys


_BASH_SCRIPT = """\
# meshtastic-sdr bash completion
eval "$(register-python-argcomplete meshtastic-sdr)"
"""

_ZSH_SCRIPT = """\
# meshtastic-sdr zsh completion
autoload -U bashcompinit
bashcompinit
eval "$(register-python-argcomplete meshtastic-sdr)"
"""

_FISH_SCRIPT = """\
# meshtastic-sdr fish completion
register-python-argcomplete --shell fish meshtastic-sdr | source
"""


def print_completion_script(shell: str) -> None:
    """Print the shell completion activation script."""
    scripts = {
        "bash": _BASH_SCRIPT,
        "zsh": _ZSH_SCRIPT,
        "fish": _FISH_SCRIPT,
    }
    script = scripts.get(shell)
    if script is None:
        print(f"Unsupported shell: {shell!r}", file=sys.stderr)
        print(f"Supported shells: {', '.join(scripts)}", file=sys.stderr)
        sys.exit(1)
    print(script.strip())
