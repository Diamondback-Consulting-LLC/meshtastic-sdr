"""BlueZ D-Bus pairing agent for accepting BLE bonding requests.

Android Meshtastic app calls createBond() when connecting to a BLE
peripheral. Without a registered BlueZ agent, bonding fails with
"Bonding failed: null". This module registers a NoInputNoOutput agent
that accepts all pairing requests (Just Works pairing).
"""

import logging

logger = logging.getLogger(__name__)

AGENT_PATH = "/org/meshtastic/sdr/agent"
AGENT_CAPABILITY = "NoInputNoOutput"

# Module-level references to keep the D-Bus connection and agent alive.
# If these get garbage collected, the agent disconnects from BlueZ.
_agent_bus = None
_agent_obj = None
_agent_registered = False


async def register_pairing_agent():
    """Register a BlueZ pairing agent via D-Bus to handle bonding requests.

    Uses NoInputNoOutput capability for Just Works pairing (no PIN).
    This must be called before starting the BLE GATT server.

    The D-Bus connection and agent object are kept alive at module level
    so the agent stays registered for the lifetime of the process.
    """
    global _agent_registered, _agent_bus, _agent_obj
    if _agent_registered:
        return

    try:
        from dbus_next.aio import MessageBus
        from dbus_next import BusType, Variant
        from dbus_next.service import ServiceInterface, method
    except ImportError:
        logger.warning("dbus_next not available, skipping pairing agent registration")
        return

    class Agent(ServiceInterface):
        """org.bluez.Agent1 implementation — accepts all pairing requests."""

        def __init__(self):
            super().__init__("org.bluez.Agent1")

        @method()
        def Release(self):  # noqa: N802
            logger.debug("Agent released")

        @method()
        def RequestPinCode(self, device: "o") -> "s":  # type: ignore # noqa: N802
            logger.info("Pairing PIN requested for %s, returning empty", device)
            return ""

        @method()
        def DisplayPinCode(self, device: "o", pincode: "s"):  # type: ignore # noqa: N802
            logger.info("Display PIN %s for %s", pincode, device)

        @method()
        def RequestPasskey(self, device: "o") -> "u":  # type: ignore # noqa: N802
            logger.info("Passkey requested for %s, returning 0", device)
            return 0

        @method()
        def DisplayPasskey(self, device: "o", passkey: "u", entered: "q"):  # type: ignore # noqa: N802
            logger.info("Display passkey %d for %s", passkey, device)

        @method()
        def RequestConfirmation(self, device: "o", passkey: "u"):  # type: ignore # noqa: N802
            logger.info("Auto-confirming pairing for %s (passkey=%d)", device, passkey)

        @method()
        def RequestAuthorization(self, device: "o"):  # type: ignore # noqa: N802
            logger.info("Auto-authorizing %s", device)

        @method()
        def AuthorizeService(self, device: "o", uuid: "s"):  # type: ignore # noqa: N802
            logger.info("Auto-authorizing service %s for %s", uuid, device)

        @method()
        def Cancel(self):  # noqa: N802
            logger.debug("Agent cancelled")

    try:
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        agent = Agent()
        bus.export(AGENT_PATH, agent)

        # Register with BlueZ AgentManager
        introspection = await bus.introspect("org.bluez", "/org/bluez")
        proxy = bus.get_proxy_object("org.bluez", "/org/bluez", introspection)
        agent_manager = proxy.get_interface("org.bluez.AgentManager1")

        await agent_manager.call_register_agent(AGENT_PATH, AGENT_CAPABILITY)
        await agent_manager.call_request_default_agent(AGENT_PATH)

        # Keep references alive at module level
        _agent_bus = bus
        _agent_obj = agent
        _agent_registered = True
        logger.info("BlueZ pairing agent registered (NoInputNoOutput / Just Works)")

        # Ensure adapter is pairable and discoverable for Android bonding
        try:
            adapter_intro = await bus.introspect("org.bluez", "/org/bluez/hci0")
            adapter_proxy = bus.get_proxy_object("org.bluez", "/org/bluez/hci0", adapter_intro)
            props = adapter_proxy.get_interface("org.freedesktop.DBus.Properties")

            await props.call_set("org.bluez.Adapter1", "Pairable", Variant("b", True))
            await props.call_set("org.bluez.Adapter1", "PairableTimeout", Variant("u", 0))
            await props.call_set("org.bluez.Adapter1", "Discoverable", Variant("b", True))
            await props.call_set("org.bluez.Adapter1", "DiscoverableTimeout", Variant("u", 0))
            logger.info("Bluetooth adapter set to pairable + discoverable")
        except Exception as e:
            logger.warning("Could not configure adapter: %s", e)

    except Exception as e:
        logger.warning("Failed to register pairing agent: %s", e)
        logger.warning("Android bonding may fail. Ensure bluetoothd is running.")
