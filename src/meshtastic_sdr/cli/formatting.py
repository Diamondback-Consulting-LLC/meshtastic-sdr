"""Shared output formatting for CLI commands."""

import time

from ..protocol.portnums import describe_portnum


def format_packet(packet, node_db=None) -> str:
    """Format a received MeshPacket for display.

    Args:
        packet: MeshPacket to format
        node_db: Optional dict mapping node_id -> NodeInfo for name lookup

    Returns:
        Formatted string like "[HH:MM:SS] !abcd1234: Hello world"
    """
    ts = time.strftime("%H:%M:%S")
    src_id = packet.header.from_node
    src = f"!{src_id:08x}"

    # Try to resolve node name from db
    if node_db and src_id in node_db:
        info = node_db[src_id]
        name = info.long_name or info.short_name
        if name:
            src = f"{name} ({src})"

    if packet.data and packet.data.text:
        return f"[{ts}] {src}: {packet.data.text}"
    elif packet.data:
        port = describe_portnum(packet.data.portnum)
        return f"[{ts}] {src}: [{port}] {len(packet.data.payload)}B"
    else:
        return f"[{ts}] {src}: (encrypted, {len(packet.encrypted)}B)"


def format_status_banner(interface, config=None) -> str:
    """Format the startup status banner.

    Args:
        interface: MeshInterface instance
        config: Optional SDRConfig for extra details

    Returns:
        Multi-line status string
    """
    lines = [
        f"Node ID:    {interface.node.node_id_str}",
        f"Long Name:  {interface.node.long_name}",
        f"Short Name: {interface.node.short_name}",
        f"Region:     {interface.region}",
        f"Preset:     {interface.preset.name}",
        f"  SF{interface.preset.spreading_factor} / "
        f"{interface.preset.bandwidth // 1000}kHz / "
        f"CR 4/{interface.preset.cr_denom}",
        f"Frequency:  {interface.frequency / 1e6:.3f} MHz",
        f"Channel:    {interface.channel.display_name} "
        f"(hash=0x{interface.channel.channel_hash:02x})",
        f"Encrypted:  {interface.channel.has_encryption()}",
        f"Backend:    {interface.radio.device_name}",
    ]
    return "\n".join(lines)
