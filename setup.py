from setuptools import setup, find_packages

setup(
    name="meshtastic-sdr",
    version="0.1.0",
    description="Meshtastic transceiver using BladeRF x40 SDR",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9",
    install_requires=[
        "numpy>=1.24",
        "protobuf>=4.0",
        "pycryptodome>=3.19",
        "pyyaml>=6.0",
    ],
    extras_require={
        "bladerf": ["bladerf"],
        "ble": ["bleak>=0.21", "bless>=0.2"],
        "ble-central": ["bleak>=0.21"],
        "ble-peripheral": ["bless>=0.2"],
    },
    entry_points={
        "console_scripts": [
            "meshtastic-sdr=meshtastic_sdr.cli.main:main",
        ],
    },
)
