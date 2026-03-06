"""Tests for shell completion subcommand."""

import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, "src")

from meshtastic_sdr.cli.completion import print_completion_script


class TestPrintCompletionScript:
    def test_bash_output(self, capsys):
        print_completion_script("bash")
        output = capsys.readouterr().out
        assert "register-python-argcomplete" in output
        assert "meshtastic-sdr" in output
        assert "eval" in output

    def test_zsh_output(self, capsys):
        print_completion_script("zsh")
        output = capsys.readouterr().out
        assert "register-python-argcomplete" in output
        assert "bashcompinit" in output
        assert "meshtastic-sdr" in output

    def test_fish_output(self, capsys):
        print_completion_script("fish")
        output = capsys.readouterr().out
        assert "register-python-argcomplete" in output
        assert "--shell fish" in output
        assert "meshtastic-sdr" in output

    def test_unsupported_shell(self):
        with pytest.raises(SystemExit):
            print_completion_script("powershell")

    def test_bash_is_evaluable(self, capsys):
        """Bash output should be a single eval-able string."""
        print_completion_script("bash")
        output = capsys.readouterr().out
        # Should not contain Python tracebacks or error messages
        assert "Traceback" not in output
        assert "Error" not in output
