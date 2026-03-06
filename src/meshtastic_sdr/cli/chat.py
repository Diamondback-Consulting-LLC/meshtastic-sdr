"""Interactive chat mode for Meshtastic SDR.

Combines listen + send in a single REPL session using stdlib cmd module.
"""

import cmd
import os
import readline
import sys
import threading
import time

from .formatting import format_packet, format_status_banner


# History file location
_HISTORY_DIR = os.path.expanduser("~/.local/share/meshtastic-sdr")
_HISTORY_FILE = os.path.join(_HISTORY_DIR, "chat_history")


class MeshChat(cmd.Cmd):
    """Interactive Meshtastic chat REPL.

    Free text (no / prefix) sends as broadcast text message.
    Commands start with / (e.g. /info, /nodes, /quit).
    """

    prompt = "mesh> "
    intro = "Meshtastic SDR interactive chat. Type /help for commands, or just type to send.\n"

    def __init__(self, interface, config=None):
        super().__init__()
        self.interface = interface
        self.config = config
        self._print_lock = threading.Lock()

    def preloop(self):
        """Load command history."""
        try:
            readline.read_history_file(_HISTORY_FILE)
        except (FileNotFoundError, OSError):
            pass

        # Start receiving packets in background
        self.interface.start_receive(self._on_packet)

    def postloop(self):
        """Save command history and clean up."""
        try:
            os.makedirs(_HISTORY_DIR, exist_ok=True)
            readline.write_history_file(_HISTORY_FILE)
        except OSError:
            pass

    def precmd(self, line):
        """Strip leading / so cmd.Cmd dispatches /info -> do_info."""
        stripped = line.strip()
        if stripped.startswith("/"):
            return stripped[1:]
        return line

    def default(self, line):
        """Send free text as broadcast message."""
        text = line.strip()
        if not text:
            return
        try:
            packet = self.interface.send_text(text)
            self._safe_print(f"Sent: {text!r} (id=0x{packet.header.id:08x})")
        except Exception as e:
            self._safe_print(f"Send error: {e}")

    def emptyline(self):
        """Do nothing on empty input (don't repeat last command)."""
        pass

    def do_help(self, arg):
        """Show available commands."""
        if arg:
            # Delegate to cmd.Cmd for specific command help
            super().do_help(arg)
            return
        lines = [
            "Commands (prefix with /):",
            "  /help              Show this help",
            "  /info              Show node, channel, and radio info",
            "  /nodes             List known nodes",
            "  /send <id> <msg>   Send DM to node (e.g. /send !abcd1234 hello)",
            "  /channel           Show channel details",
            "  /quit              Exit chat mode",
            "",
            "Type any text without / to send as broadcast message.",
        ]
        self._safe_print("\n".join(lines))

    def do_info(self, arg):
        """Show node and radio info."""
        banner = format_status_banner(self.interface, self.config)
        self._safe_print(banner)

    def do_nodes(self, arg):
        """List known mesh nodes."""
        nodes = self.interface.node.known_nodes
        if not nodes:
            self._safe_print("No nodes discovered yet.")
            return
        lines = [f"Known nodes ({len(nodes)}):"]
        for info in nodes:
            name = info.long_name or info.short_name or ""
            ago = ""
            if info.last_heard:
                secs = time.time() - info.last_heard
                if secs < 60:
                    ago = f"{secs:.0f}s ago"
                elif secs < 3600:
                    ago = f"{secs / 60:.0f}m ago"
                else:
                    ago = f"{secs / 3600:.1f}h ago"
            line = f"  {info.node_id_str}"
            if name:
                line += f"  {name}"
            if ago:
                line += f"  (heard {ago})"
            lines.append(line)
        self._safe_print("\n".join(lines))

    def do_send(self, arg):
        """Send a DM to a specific node: /send <node_id> <message>"""
        parts = arg.strip().split(None, 1)
        if len(parts) < 2:
            self._safe_print("Usage: /send <node_id> <message>")
            self._safe_print("  node_id: !hexid (e.g. !abcd1234) or decimal")
            return

        node_str, message = parts
        try:
            if node_str.startswith("!"):
                node_id = int(node_str[1:], 16)
            else:
                node_id = int(node_str)
        except ValueError:
            self._safe_print(f"Invalid node ID: {node_str}")
            return

        try:
            packet = self.interface.send_text(message, to=node_id)
            self._safe_print(f"DM to {node_str}: {message!r} (id=0x{packet.header.id:08x})")
        except Exception as e:
            self._safe_print(f"Send error: {e}")

    def do_channel(self, arg):
        """Show channel configuration details."""
        ch = self.interface.channel
        lines = [
            f"Channel:  {ch.display_name}",
            f"Hash:     0x{ch.channel_hash:02x}",
            f"Index:    {ch.index}",
            f"Encrypted: {ch.has_encryption()}",
        ]
        self._safe_print("\n".join(lines))

    def do_quit(self, arg):
        """Exit chat mode."""
        self._safe_print("Goodbye.")
        return True

    def do_exit(self, arg):
        """Exit chat mode."""
        return self.do_quit(arg)

    def do_EOF(self, arg):
        """Handle Ctrl+D."""
        print()  # newline after ^D
        return self.do_quit(arg)

    def complete_send(self, text, line, begidx, endidx):
        """Tab-complete node IDs for /send."""
        nodes = self.interface.node.known_nodes
        ids = [info.node_id_str for info in nodes]
        if text:
            return [nid for nid in ids if nid.startswith(text)]
        return ids

    def _on_packet(self, packet):
        """Callback for received packets — display without clobbering input."""
        node_db = self.interface.node._node_db
        msg = format_packet(packet, node_db)
        self._safe_print(msg)

    def _safe_print(self, text):
        """Print text without clobbering the user's partial input line."""
        with self._print_lock:
            # Save and restore readline state
            try:
                saved_line = readline.get_line_buffer()
                sys.stdout.write(f"\r\033[K{text}\n")
                if saved_line:
                    sys.stdout.write(f"{self.prompt}{saved_line}")
                else:
                    sys.stdout.write(self.prompt)
                sys.stdout.flush()
                readline.redisplay()
            except Exception:
                # Fallback if readline isn't fully available
                print(f"\n{text}")
