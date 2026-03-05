from .base import RadioBackend
from .simulated import SimulatedRadio

__all__ = ["RadioBackend", "SimulatedRadio"]

# Optional backends — imported on demand to avoid hard dependencies
# BladeRF: from meshtastic_sdr.radio.bladerf_radio import BladeRFRadio
# SoapySDR: from meshtastic_sdr.radio.soapy_radio import SoapyRadio
