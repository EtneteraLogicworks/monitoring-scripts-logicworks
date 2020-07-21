#!/usr/bin/env python3
"""logicworks_ubnt_lib
Library with common code for UBNT Logicworks monitoring scripts
"""

import re

import requests

from logicworks_monitoring_lib import unknown_exit

UNIFI_RELEASES_URL = "https://fw-update.ubnt.com/api/firmware-latest"
UNIFI_IDENTIFIERS = {
    "UAP-AC-EDU": "U7PG2",
    "UAP–AC–IW": "U7PG2",
    "UAP–AC–IW–PRO": "U7PG2",
    "UAP-AC-LITE": "U7PG2",
    "UAP-AC-LR": "U7PG2",
    "UAP-AC-M": "U7PG2",
    "UAP-AC-M-PRO": "U7PG2",
    "UAP-AC-PRO": "U7PG2",
    "UAP-AC-PRO-GEN2": "U7PG2",
    "UA-FLEXHD": "U7NHD",
    "UAP-BEACONHD": "U7NHD",
    "UAP-IW-HD": "U7NHD",
    "UAP-NANOHD": "U7NHD",
    "UAP-IW": "U2IW",
    "UAP-OUTDOOR+": "U2HSR",
    "UAP-HD": "U7HD",
    "UAP-SHD": "U7HD",
    "UAP‑XG": "U7HD",
    "UWB‑XG": "U7HD",
    "UWB‑XG‑BK": "U7HD",
    "UAP": "BZ2",
    "UAP-LR": "BZ2",
    "UAP-OUTDOOR": "BZ2",
    "UAP-OUTDOOR5": "BZ2",
    "UAP-V2": "U2SV2",
    "UAP-LR-V2": "U2SV2",
    "UAP-PRO": "U7P",
}


def normalize_ubnt_version(raw_version):
    """Strip unwanted characters from the retrieved version"""
    version_string = re.sub("[a-zA-Z]", "", raw_version)
    version_string = version_string.replace("+", ".")
    return version_string


def fetch_latest_ubnt_version(unifi_model, service):
    """Obtain latest available firmware version for the device from the UBNT API"""
    try:
        req = requests.get(UNIFI_RELEASES_URL)
        list_of_devices = req.json()["_embedded"]["firmware"]
    except (requests.exceptions.RequestException, ValueError) as err:
        unknown_exit(service, err)

    my_device = UNIFI_IDENTIFIERS.get(unifi_model.upper(), unifi_model.upper())

    device_item = next(
        (
            device
            for device in list_of_devices
            if device["channel"] == "release" and device["platform"] == my_device
        ),
        None,
    )
    if device_item is None:
        unknown_exit(service, f"Unable to find updates for device: {unifi_model}")
    return device_item["version"]


def generate_ubnt_update_output(installed_version, normalized_current_version, service):
    """Prepare message string and exit code"""
    if installed_version == normalized_current_version:
        state = "OK"
        message = f"{service} {state} - Firmware {installed_version} is current"
    else:
        state = "WARNING"
        message = (
            f"{service} {state} - firmware version {installed_version} "
            f"differs from the latest available {normalized_current_version}"
        )

    return state, message
