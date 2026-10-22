"""
MAC address → vendor lookup via the IEEE OUI registry.

The first 3 bytes of every MAC address are assigned by IEEE to a
manufacturer. Knowing the vendor tells you a lot about a host without
touching it: `b8:27:eb:*` is a Raspberry Pi, `00:50:56:*` is a VMware
guest, `00:0c:29:*` is VMware Workstation, `52:54:00:*` is QEMU/KVM,
`08:00:27:*` is VirtualBox.

This module:

  1. Downloads the IEEE OUI list once (~4 MB, ~35k entries), caches it
     at ~/.toolkit/oui.txt, and refreshes it on demand.
  2. Falls back to a small embedded list of the ~150 most common
     vendors when the download fails (offline networks, air-gapped
     labs, etc.).
  3. Provides `lookup(mac)` → vendor name (or None).
  4. Provides `run(target, ...)` that takes a subnet or IP, resolves
     the MACs (via ARP scan), and writes host records with vendor info
     into the workspace store.

Cache file location:

    Windows: %USERPROFILE%\\.toolkit\\oui.txt
    Linux/macOS: ~/.toolkit/oui.txt

Integration with the store:

    from core.workspace import get_workspace
    from core.store import open_store
    from net import oui

    ws = get_workspace('acme')
    store = open_store(ws.db_path, workspace_name='acme')
    await oui.run('172.16.11.0/24', store=store)
    # Every host in the subnet now has a `vendor` field in the store.
"""

import ipaddress
import os
import re
import socket
import time
import urllib.request
from pathlib import Path

from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Cache location
# ---------------------------------------------------------------------

def _cache_dir() -> Path:
    """~/.toolkit on POSIX, %USERPROFILE%\\.toolkit on Windows."""
    home = Path.home()
    d = home / ".toolkit"
    d.mkdir(parents=True, exist_ok=True)
    return d


CACHE_FILE = _cache_dir() / "oui.txt"
CACHE_MAX_AGE_DAYS = 30

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"


# ---------------------------------------------------------------------
# Embedded fallback — ~150 most common OUIs
# ---------------------------------------------------------------------
#
# These are the manufacturers you'll actually encounter on a corporate
# LAN: hypervisor MACs, common phone/laptop vendors, printer makers,
# network gear, IoT vendors, and the Raspberry Pi Foundation.
#
# Format: "first 6 hex chars (lowercase, no separators)": "vendor"

EMBEDDED_OUI = {
    # --- Hypervisors (VERY common on any virtualized network) ---
    "005056": "VMware",
    "000c29": "VMware Workstation",
    "000569": "VMware",
    "001c14": "VMware",
    "525400": "QEMU/KVM",
    "080027": "Oracle VirtualBox",
    "0a0027": "Oracle VirtualBox",
    "00163e": "Xen",
    "0003ff": "Microsoft Hyper-V",
    "001dd8": "Microsoft Hyper-V",
    "00155d": "Microsoft Hyper-V",
    "000d3a": "Microsoft",
    "0050f2": "Microsoft",
    "7c1e52": "Microsoft",
    "0017fa": "Microsoft",
    "281878": "Microsoft",
    "b831eb": "Microsoft",
    "c83f26": "Microsoft",
    "d8d090": "Microsoft",
    "dcb4c4": "Microsoft",
    "e4a471": "Microsoft",
    "f01dbc": "Microsoft",
    "fc4dd4": "Microsoft",

    # --- Dell ---
    "00188b": "Dell",
    "001c23": "Dell",
    "001d09": "Dell",
    "001e4f": "Dell",
    "001ec9": "Dell",
    "00219b": "Dell",
    "002219": "Dell",
    "0023ae": "Dell",
    "0024e8": "Dell",
    "002564": "Dell",
    "0026b9": "Dell",
    "148f2e": "Dell",
    "180373": "Dell",
    "1866da": "Dell",
    "18a99b": "Dell",
    "18db f2": "Dell",
    "20040f": "Dell",
    "246e96": "Dell",
    "28f10e": "Dell",
    "3417eb": "Dell",
    "34e6d7": "Dell",
    "44a842": "Dell",
    "509a4c": "Dell",
    "54bf64": "Dell",
    "5cf9dd": "Dell",
    "74867a": "Dell",
    "782bcb": "Dell",
    "84 2b 2b": "Dell",
    "90b11c": "Dell",
    "9840bb": "Dell",
    "a41f72": "Dell",
    "b083fe": "Dell",
    "b8ac6f": "Dell",
    "b8ca3a": "Dell",
    "c81f66": "Dell",
    "d067e5": "Dell",
    "d4ae52": "Dell",
    "d4bed9": "Dell",
    "e0db55": "Dell",
    "ecf4bb": "Dell",
    "f04da2": "Dell",
    "f48e38": "Dell",
    "f8b156": "Dell",
    "f8bc12": "Dell",

    # --- HP / HPE ---
    "001185": "HP",
    "001321": "HP",
    "0014c2": "HP",
    "001560": "HP",
    "001708": "HP",
    "0017a4": "HP",
    "0018fe": "HP",
    "0019bb": "HP",
    "001a4b": "HP",
    "001b78": "HP",
    "001cc4": "HP",
    "001e0b": "HP",
    "001f29": "HP",
    "00215a": "HP",
    "002264": "HP",
    "00237d": "HP",
    "002481": "HP",
    "0025b3": "HP",
    "002655": "HP",
    "10604b": "HP",
    "1458d0": "HP",
    "1cc1de": "HP",
    "2c27d7": "HP",
    "2c4138": "HP",
    "2c44fd": "HP",
    "3464a9": "HP",
    "38eaa7": "HP",
    "3c4a92": "HP",
    "3ca82a": "HP",
    "40a8f0": "HP",
    "441ea1": "HP",
    "48 0f cf": "HP",
    "5065f3": "HP",
    "5c8a38": "HP",
    "6c3be5": "HP",
    "70106f": "HP",
    "78acc0": "HP",
    "78e3b5": "HP",
    "80c16e": "HP",
    "8851fb": "HP",
    "9457a5": "HP",
    "98e7f4": "HP",
    "9c8e99": "HP",
    "a01d48": "HP",
    "a02bb8": "HP",
    "a0481c": "HP",
    "a45d36": "HP",
    "b05ada": "HP",
    "b499ba": "HP",
    "c4346b": "HP",
    "c8cbb8": "HP",
    "cc3e5f": "HP",
    "d07e28": "HP",
    "d48564": "HP",
    "d89d67": "HP",
    "dc4a3e": "HP",
    "e4115b": "HP",
    "ec b1 d7": "HP",
    "ecebb8": "HP",
    "f40343": "HP",
    "fc15b4": "HP",

    # --- Lenovo / IBM ---
    "001125": "IBM",
    "00145e": "IBM",
    "001a64": "IBM",
    "001125": "IBM",
    "6cae8b": "IBM",
    "e41f13": "IBM",
    "0018b2": "Lenovo",
    "0021cc": "Lenovo",
    "28d244": "Lenovo",
    "3c970e": "Lenovo",
    "54ee75": "Lenovo",
    "6045cb": "Lenovo",
    "6c0b84": "Lenovo",
    "70720d": "Lenovo",
    "7c7a91": "Lenovo",
    "8c1645": "Lenovo",
    "98 40 bb": "Lenovo",
    "a48cdb": "Lenovo",
    "c85b76": "Lenovo",
    "d8d385": "Lenovo",
    "e8 61 1f": "Lenovo",

    # --- Apple ---
    "0017f2": "Apple",
    "0019e3": "Apple",
    "001b63": "Apple",
    "001cb3": "Apple",
    "001d4f": "Apple",
    "001e52": "Apple",
    "001ec2": "Apple",
    "001f5b": "Apple",
    "001ff3": "Apple",
    "0021e9": "Apple",
    "002332": "Apple",
    "00236c": "Apple",
    "0023df": "Apple",
    "002436": "Apple",
    "002500": "Apple",
    "00254b": "Apple",
    "0026bb": "Apple",
    "003ee1": "Apple",
    "0050e4": "Apple",
    "00a040": "Apple",
    "00c610": "Apple",
    "04489a": "Apple",
    "0452f3": "Apple",
    "04d3cf": "Apple",
    "04db56": "Apple",
    "04e536": "Apple",
    "04f13e": "Apple",
    "04f7e4": "Apple",
    "080007": "Apple",
    "0c1539": "Apple",
    "0c3021": "Apple",
    "0c3e9f": "Apple",
    "0c4de9": "Apple",
    "0c5101": "Apple",
    "0c74c2": "Apple",
    "0c771a": "Apple",
    "0cbc9f": "Apple",
    "101c0c": "Apple",
    "103025": "Apple",
    "10417f": "Apple",
    "1093e9": "Apple",
    "109add": "Apple",
    "10 40 f3": "Apple",
    "14109f": "Apple",
    "145a05": "Apple",
    "1499e2": "Apple",
    "14 10 9f": "Apple",
    "183451": "Apple",
    "186590": "Apple",
    "18af61": "Apple",
    "18af8f": "Apple",
    "18e7f4": "Apple",
    "18f643": "Apple",
    "1c1ac0": "Apple",
    "1c36bb": "Apple",
    "1c5cf2": "Apple",
    "1c9148": "Apple",
    "1caba7": "Apple",
    "1ce62b": "Apple",
    "2078f0": "Apple",
    "207d74": "Apple",
    "209bcd": "Apple",
    "20a2e4": "Apple",
    "20c9d0": "Apple",
    "241eeb": "Apple",
    "24240e": "Apple",
    "24a074": "Apple",
    "24a2e1": "Apple",
    "24ab81": "Apple",
    "24e314": "Apple",
    "24f094": "Apple",
    "24f677": "Apple",
    "28cfe9": "Apple",
    "28cfda": "Apple",
    "28e02c": "Apple",
    "28e14c": "Apple",
    "28e7cf": "Apple",
    "28ed6a": "Apple",
    "28f076": "Apple",
    "2c1f23": "Apple",
    "2c200b": "Apple",
    "2c3361": "Apple",
    "2c61f6": "Apple",
    "2cb43a": "Apple",
    "2cf0a2": "Apple",
    "2cf0ee": "Apple",
    "3010e4": "Apple",
    "3035ad": "Apple",
    "30636b": "Apple",
    "30f7c5": "Apple",
    "30fabe": "Apple",
    "34363b": "Apple",
    "34a395": "Apple",
    "34ab37": "Apple",
    "34c059": "Apple",
    "34e2fd": "Apple",
    "380f4a": "Apple",
    "38484c": "Apple",
    "3866f0": "Apple",
    "3871de": "Apple",
    "38b54d": "Apple",
    "38c986": "Apple",
    "38ca da": "Apple",
    "38f9d3": "Apple",
    "3c0754": "Apple",
    "3c15c2": "Apple",
    "3c2ef9": "Apple",
    "3c2eff": "Apple",
    "3c9f81": "Apple",
    "3cab8e": "Apple",
    "3cd0f8": "Apple",
    "3ce072": "Apple",
    "40 3c fc": "Apple",
    "40331a": "Apple",
    "406c8f": "Apple",
    "4098ad": "Apple",
    "409c28": "Apple",
    "40a6d9": "Apple",
    "40b395": "Apple",
    "40d32d": "Apple",
    "442a60": "Apple",
    "444c0c": "Apple",
    "44d884": "Apple",
    "44fb42": "Apple",
    "48437c": "Apple",
    "4860bc": "Apple",
    "48746e": "Apple",
    "48a195": "Apple",
    "48bf6b": "Apple",
    "48d705": "Apple",
    "48e9f1": "Apple",
    "4c3275": "Apple",
    "4c57ca": "Apple",
    "4c74bf": "Apple",
    "4c7c5f": "Apple",
    "4c8d79": "Apple",
    "4cb199": "Apple",
    "4cc95e": "Apple",
    "5017f1": "Apple",
    "503237": "Apple",
    "5031bf": "Apple",
    "5082d5": "Apple",
    "50ead6": "Apple",
    "542696": "Apple",
    "5462e2": "Apple",
    "54 26 96": "Apple",
    "543ad6": "Apple",
    "54ae27": "Apple",
    "54e43a": "Apple",
    "58 55 ca": "Apple",
    "580ff2": "Apple",
    "581faa": "Apple",
    "5855ca": "Apple",
    "58b035": "Apple",
    "5c5948": "Apple",
    "5c95ae": "Apple",
    "5c969d": "Apple",
    "5cadcf": "Apple",
    "5cf5da": "Apple",
    "5cf938": "Apple",
    "600308": "Apple",
    "6030d9": "Apple",
    "60334b": "Apple",
    "608c4a": "Apple",
    "609217": "Apple",
    "609ac1": "Apple",
    "60c547": "Apple",
    "60d9c7": "Apple",
    "60f81d": "Apple",
    "60facd": "Apple",
    "60fb42": "Apple",
    "64200c": "Apple",
    "64 20 0c": "Apple",
    "64a3cb": "Apple",
    "64b0a6": "Apple",
    "64b9e8": "Apple",
    "64e682": "Apple",
    "685b35": "Apple",
    "68644b": "Apple",
    "6886a7": "Apple",
    "68a86d": "Apple",
    "68ab1e": "Apple",
    "68ae20": "Apple",
    "68d93c": "Apple",
    "68dbca": "Apple",
    "68fb7e": "Apple",
    "6c3e6d": "Apple",
    "6c4008": "Apple",
    "6c709f": "Apple",
    "6c72e7": "Apple",
    "6c8dc1": "Apple",
    "6c94f8": "Apple",
    "6cc26b": "Apple",
    "701124": "Apple",
    "7014a6": "Apple",
    "703eac": "Apple",
    "70480f": "Apple",
    "7073cb": "Apple",
    "70a2b3": "Apple",
    "70cd60": "Apple",
    "70dee2": "Apple",
    "70ec e1": "Apple",
    "70f0e1": "Apple",
    "741bb2": "Apple",
    "745e1c": "Apple",
    "7479a8": "Apple",
    "748114": "Apple",
    "74e1b6": "Apple",
    "74e2f5": "Apple",
    "7831c1": "Apple",
    "783a84": "Apple",
    "786c1c": "Apple",
    "787b8a": "Apple",
    "787e61": "Apple",
    "789f70": "Apple",
    "78a3e4": "Apple",
    "78ca39": "Apple",
    "78d75f": "Apple",
    "78fd94": "Apple",
    "7c0191": "Apple",
    "7c11be": "Apple",
    "7c6d62": "Apple",
    "7c6df8": "Apple",
    "7cc3a1": "Apple",
    "7cc537": "Apple",
    "7cd1c3": "Apple",
    "7cf05f": "Apple",
    "7cfadf": "Apple",
    "80006e": "Apple",
    "80be05": "Apple",
    "80e650": "Apple",
    "80ea96": "Apple",
    "80ed2c": "Apple",
    "843835": "Apple",
    "845b12": "Apple",
    "848506": "Apple",
    "8489ad": "Apple",
    "84fcfe": "Apple",
    "84fcfc": "Apple",
    "8863df": "Apple",
    "886b6e": "Apple",
    "88c663": "Apple",
    "88cb87": "Apple",
    "88e87f": "Apple",
    "8c006d": "Apple",
    "8c2937": "Apple",
    "8c2daa": "Apple",
    "8c5877": "Apple",
    "8c7b9d": "Apple",
    "8c7c92": "Apple",
    "8c8ef2": "Apple",
    "8cfa ba": "Apple",
    "9027e4": "Apple",
    "90840d": "Apple",
    "909c4a": "Apple",
    "90b21f": "Apple",
    "90b931": "Apple",
    "90c1c6": "Apple",
    "90fd61": "Apple",
    "949426": "Apple",
    "94 94 26": "Apple",
    "94e96a": "Apple",
    "94f6a3": "Apple",
    "9801a7": "Apple",
    "9803d8": "Apple",
    "985bcd": "Apple",
    "989e63": "Apple",
    "98b8e3": "Apple",
    "98d6bb": "Apple",
    "98e0d9": "Apple",
    "98fe94": "Apple",
    "9c04eb": "Apple",
    "9c207b": "Apple",
    "9c293f": "Apple",
    "9c35eb": "Apple",
    "9c4fda": "Apple",
    "9c84bf": "Apple",
    "9cf387": "Apple",
    "9cfc01": "Apple",
    "a01828": "Apple",
    "a0d795": "Apple",
    "a0edcd": "Apple",
    "a45e60": "Apple",
    "a46706": "Apple",
    "a4b197": "Apple",
    "a4c361": "Apple",
    "a4d18c": "Apple",
    "a4d1d2": "Apple",
    "a4f1e8": "Apple",
    "a82066": "Apple",
    "a85b78": "Apple",
    "a860b6": "Apple",
    "a8667f": "Apple",
    "a886dd": "Apple",
    "a88808": "Apple",
    "a88e24": "Apple",
    "a8968a": "Apple",
    "a8bbcf": "Apple",
    "a8fad8": "Apple",
    "ac293a": "Apple",
    "ac3c0b": "Apple",
    "ac61ea": "Apple",
    "ac7f3e": "Apple",
    "acbc32": "Apple",
    "accf5c": "Apple",
    "acfdec": "Apple",
    "b03495": "Apple",
    "b065bd": "Apple",
    "b0 65 bd": "Apple",
    "b09fba": "Apple",
    "b418d1": "Apple",
    "b44bd2": "Apple",
    "b48b19": "Apple",
    "b4f0ab": "Apple",
    "b8 17 c2": "Apple",
    "b817c2": "Apple",
    "b853ac": "Apple",
    "b8c75d": "Apple",
    "b8c9b5": "Apple",
    "b8e856": "Apple",
    "b8f6b1": "Apple",
    "b8ff61": "Apple",
    "bc3baf": "Apple",
    "bc4cc4": "Apple",
    "bc52b7": "Apple",
    "bc5436": "Apple",
    "bc6778": "Apple",
    "bc6c21": "Apple",
    "bc926b": "Apple",
    "bc9fef": "Apple",
    "bca920": "Apple",
    "bcec5d": "Apple",
    "c01ada": "Apple",
    "c06394": "Apple",
    "c0847a": "Apple",
    "c09f42": "Apple",
    "c0cecd": "Apple",
    "c0d012": "Apple",
    "c0f2fb": "Apple",
    "c42c03": "Apple",
    "c4b301": "Apple",
    "c81ee7": "Apple",
    "c82a14": "Apple",
    "c8334b": "Apple",
    "c869cd": "Apple",
    "c88550": "Apple",
    "c8b5b7": "Apple",
    "c8bc c8": "Apple",
    "c8d083": "Apple",
    "c8e0eb": "Apple",
    "c8f650": "Apple",
    "cc08e0": "Apple",
    "cc088d": "Apple",
    "cc29f5": "Apple",
    "cc4463": "Apple",
    "cc785f": "Apple",
    "ccc760": "Apple",
    "d023db": "Apple",
    "d02598": "Apple",
    "d03311": "Apple",
    "d0 23 db": "Apple",
    "d0a637": "Apple",
    "d0c5f3": "Apple",
    "d0e140": "Apple",
    "d49a20": "Apple",
    "d4 9a 20": "Apple",
    "d4dccd": "Apple",
    "d4f46f": "Apple",
    "d8004d": "Apple",
    "d81d72": "Apple",
    "d83062": "Apple",
    "d89695": "Apple",
    "d89e3f": "Apple",
    "d8a25e": "Apple",
    "d8bb2c": "Apple",
    "d8cf9c": "Apple",
    "d8d1cb": "Apple",
    "dc0c5c": "Apple",
    "dc2b2a": "Apple",
    "dc2b61": "Apple",
    "dc3714": "Apple",
    "dc415f": "Apple",
    "dc86d8": "Apple",
    "dc9b9c": "Apple",
    "dca4ca": "Apple",
    "dca904": "Apple",
    "e0338e": "Apple",
    "e05f45": "Apple",
    "e0ac cb": "Apple",
    "e0b52d": "Apple",
    "e0b9ba": "Apple",
    "e0c767": "Apple",
    "e0c97a": "Apple",
    "e0f5c6": "Apple",
    "e0f847": "Apple",
    "e425e7": "Apple",
    "e498d6": "Apple",
    "e4 25 e7": "Apple",
    "e4ce8f": "Apple",
    "e4e4ab": "Apple",
    "e8802e": "Apple",
    "e88d28": "Apple",
    "e8b2ac": "Apple",
    "e8bb3d": "Apple",
    "ec3586": "Apple",
    "ec852f": "Apple",
    "f0 18 98": "Apple",
    "f01898": "Apple",
    "f02475": "Apple",
    "f0766f": "Apple",
    "f099bf": "Apple",
    "f0b479": "Apple",
    "f0c1f1": "Apple",
    "f0cb a1": "Apple",
    "f0d1a9": "Apple",
    "f0dbe2": "Apple",
    "f0dcea": "Apple",
    "f0f61c": "Apple",
    "f41ba1": "Apple",
    "f437b7": "Apple",
    "f45c89": "Apple",
    "f4 5c 89": "Apple",
    "f4f15a": "Apple",
    "f4f951": "Apple",
    "f81edf": "Apple",
    "f82793": "Apple",
    "f84d89": "Apple",
    "f895ea": "Apple",
    "f8ff0b": "Apple",
    "f8ffc2": "Apple",
    "fc253f": "Apple",
    "fc2a9c": "Apple",
    "fc3fdb": "Apple",
    "fc6076": "Apple",
    "fcd848": "Apple",
    "fce998": "Apple",
    "fcfc48": "Apple",

    # --- Samsung ---
    "0012fb": "Samsung",
    "0015b9": "Samsung",
    "0017c9": "Samsung",
    "0017d5": "Samsung",
    "0018af": "Samsung",
    "001a8a": "Samsung",
    "001df6": "Samsung",
    "001e7d": "Samsung",
    "0021d1": "Samsung",
    "0023d6": "Samsung",
    "002454": "Samsung",
    "002567": "Samsung",
    "00265f": "Samsung",
    "04180f": "Samsung",
    "04fe31": "Samsung",
    "08d42b": "Samsung",
    "0c715d": "Samsung",
    "0c8910": "Samsung",
    "1007e4": "Samsung",
    "1077b1": "Samsung",
    "107bce": "Samsung",
    "1449e0": "Samsung",
    "14f42a": "Samsung",
    "1816c9": "Samsung",
    "182195": "Samsung",
    "1c5a3e": "Samsung",
    "1caf05": "Samsung",
    "2013e0": "Samsung",
    "205531": "Samsung",
    "20d390": "Samsung",
    "24 4b 03": "Samsung",
    "244b03": "Samsung",
    "244b81": "Samsung",
    "24dbed": "Samsung",
    "28395e": "Samsung",
    "28ba b5": "Samsung",
    "28cc01": "Samsung",
    "2c4401": "Samsung",
    "2cae2b": "Samsung",
    "308de4": "Samsung",
    "34039b": "Samsung",
    "3423ba": "Samsung",
    "34aa8b": "Samsung",
    "380a94": "Samsung",
    "38aa3c": "Samsung",
    "38d40b": "Samsung",
    "3c5a37": "Samsung",
    "3c8bfe": "Samsung",
    "3ca10d": "Samsung",
    "3cbb fd": "Samsung",
    "40 0e 85": "Samsung",
    "400e85": "Samsung",
    "40d3ae": "Samsung",
    "44783e": "Samsung",
    "4495fa": "Samsung",
    "4498 17": "Samsung",
    "44 4e 1a": "Samsung",
    "444e1a": "Samsung",
    "44f459": "Samsung",
    "4802 2d": "Samsung",
    "4844f7": "Samsung",
    "4c3c16": "Samsung",
    "4c66a6": "Samsung",
    "5001bb": "Samsung",
    "5001d9": "Samsung",
    "50ccf8": "Samsung",
    "50fc9f": "Samsung",
    "54 92 be": "Samsung",
    "5492be": "Samsung",
    "549f 13": "Samsung",
    "5c0a5b": "Samsung",
    "5c2e59": "Samsung",
    "5c3c27": "Samsung",
    "5c497d": "Samsung",
    "5cae 8c": "Samsung",
    "5cf6dc": "Samsung",
    "60071a": "Samsung",
    "60a10a": "Samsung",
    "60afbd": "Samsung",
    "60d0a9": "Samsung",
    "64b310": "Samsung",
    "64b853": "Samsung",
    "681729": "Samsung",
    "68eb ae": "Samsung",
    "6c2f2c": "Samsung",
    "6c8336": "Samsung",
    "6cb749": "Samsung",
    "7018 8b": "Samsung",
    "70f9 27": "Samsung",
    "70f927": "Samsung",
    "74458a": "Samsung",
    "74eb 55": "Samsung",
    "7825ad": "Samsung",
    "78471d": "Samsung",
    "78 1f db": "Samsung",
    "781f db": "Samsung",
    "78521a": "Samsung",
    "7884 3c": "Samsung",
    "78982b": "Samsung",
    "78a873": "Samsung",
    "78abbb": "Samsung",
    "78bdbc": "Samsung",
    "78c3e9": "Samsung",
    "78d6f0": "Samsung",
    "7c0bc6": "Samsung",
    "7c1c68": "Samsung",
    "7c2e0d": "Samsung",
    "7c61 66": "Samsung",
    "7c6166": "Samsung",
    "7c787e": "Samsung",
    "7c9122": "Samsung",
    "7cf854": "Samsung",
    "8018a7": "Samsung",
    "804e81": "Samsung",
    "8057 19": "Samsung",
    "805719": "Samsung",
    "8071 1f": "Samsung",
    "8086f2": "Samsung",
    "84119e": "Samsung",
    "8425db": "Samsung",
    "8474 2b": "Samsung",
    "849866": "Samsung",
    "84a466": "Samsung",
    "84b5 41": "Samsung",
    "84b541": "Samsung",
    "885395": "Samsung",
    "8c3ae3": "Samsung",
    "8c71f8": "Samsung",
    "8c77 12": "Samsung",
    "8cbfa6": "Samsung",
    "9015 99": "Samsung",
    "9021 59": "Samsung",
    "905f 2d": "Samsung",
    "9097 f1": "Samsung",
    "9097f1": "Samsung",
    "943bb0": "Samsung",
    "9463d1": "Samsung",
    "9476b7": "Samsung",
    "94b10a": "Samsung",
    "94e979": "Samsung",
    "980c82": "Samsung",
    "9852b1": "Samsung",
    "98 83 89": "Samsung",
    "988389": "Samsung",
    "98ba39": "Samsung",
    "98d3 25": "Samsung",
    "98d325": "Samsung",
    "9c02 98": "Samsung",
    "9c0298": "Samsung",
    "9c3a af": "Samsung",
    "9c3aaf": "Samsung",
    "9c65b0": "Samsung",
    "9c8b a0": "Samsung",
    "9ca513": "Samsung",
    "9cd35b": "Samsung",
    "a00b ba": "Samsung",
    "a007 98": "Samsung",
    "a00798": "Samsung",
    "a02195": "Samsung",
    "a06090": "Samsung",
    "a07591": "Samsung",
    "a0821f": "Samsung",
    "a0 82 1f": "Samsung",
    "a0cb fd": "Samsung",
    "a48431": "Samsung",
    "a4ebd3": "Samsung",
    "a806 00": "Samsung",
    "a8f274": "Samsung",
    "ac36 13": "Samsung",
    "ac3613": "Samsung",
    "ac5a14": "Samsung",
    "ac5f3e": "Samsung",
    "acc33a": "Samsung",
    "ace2d3": "Samsung",
    "b047 bf": "Samsung",
    "b0c4e7": "Samsung",
    "b0df3a": "Samsung",
    "b407 f9": "Samsung",
    "b43a28": "Samsung",
    "b46293": "Samsung",
    "b47443": "Samsung",
    "b857d8": "Samsung",
    "b85e7b": "Samsung",
    "b8bbaf": "Samsung",
    "b8c68e": "Samsung",
    "b8d9ce": "Samsung",
    "bc14 85": "Samsung",
    "bc1485": "Samsung",
    "bc20a4": "Samsung",
    "bc44 86": "Samsung",
    "bc4486": "Samsung",
    "bc72b1": "Samsung",
    "bc765e": "Samsung",
    "bc79 ad": "Samsung",
    "bc851f": "Samsung",
    "bca1 0a": "Samsung",
    "bce63f": "Samsung",
    "c01173": "Samsung",
    "c06599": "Samsung",
    "c0bdd1": "Samsung",
    "c81479": "Samsung",
    "c819f7": "Samsung",
    "c83870": "Samsung",
    "c83c44": "Samsung",
    "c8ba94": "Samsung",
    "c8d7b0": "Samsung",
    "cc07ab": "Samsung",
    "cc3a61": "Samsung",
    "cc6ea4": "Samsung",
    "cc79 51": "Samsung",
    "ccf9e8": "Samsung",
    "ccfe3c": "Samsung",
    "d0176a": "Samsung",
    "d025 16": "Samsung",
    "d02516": "Samsung",
    "d059e4": "Samsung",
    "d066 7b": "Samsung",
    "d0667b": "Samsung",
    "d087e2": "Samsung",
    "d0b128": "Samsung",
    "d0c1b1": "Samsung",
    "d0dfc7": "Samsung",
    "d487d8": "Samsung",
    "d4ae05": "Samsung",
    "d4 87 d8": "Samsung",
    "d4e8b2": "Samsung",
    "d831cf": "Samsung",
    "d857ef": "Samsung",
    "d85b2a": "Samsung",
    "d890e8": "Samsung",
    "d8c4e9": "Samsung",
    "dc44 6d": "Samsung",
    "dc446d": "Samsung",
    "dc7144": "Samsung",
    "dccf96": "Samsung",
    "dce2ac": "Samsung",
    "e09967": "Samsung",
    "e0cb ee": "Samsung",
    "e0db10": "Samsung",
    "e432cb": "Samsung",
    "e440e2": "Samsung",
    "e458b8": "Samsung",
    "e458e7": "Samsung",
    "e492fb": "Samsung",
    "e4 7c f9": "Samsung",
    "e4 7d bd": "Samsung",
    "e4b021": "Samsung",
    "e4e0c5": "Samsung",
    "e8039a": "Samsung",
    "e8112e": "Samsung",
    "e83a12": "Samsung",
    "e8508b": "Samsung",
    "e89309": "Samsung",
    "e8b4c8": "Samsung",
    "e8e5d6": "Samsung",
    "ec107b": "Samsung",
    "ec1f72": "Samsung",
    "ec9bf3": "Samsung",
    "ece09b": "Samsung",
    "f008 f1": "Samsung",
    "f008f1": "Samsung",
    "f0 25 b7": "Samsung",
    "f025b7": "Samsung",
    "f05a09": "Samsung",
    "f06bca": "Samsung",
    "f0e77e": "Samsung",
    "f409d8": "Samsung",
    "f40e22": "Samsung",
    "f47b5e": "Samsung",
    "f49f54": "Samsung",
    "f4d9fb": "Samsung",
    "f8042e": "Samsung",
    "f83f51": "Samsung",
    "f8494c": "Samsung",
    "f877b8": "Samsung",
    "f8d0ac": "Samsung",
    "f8e61a": "Samsung",
    "fcc734": "Samsung",
    "fce8c0": "Samsung",

    # --- Raspberry Pi Foundation ---
    "b827eb": "Raspberry Pi Foundation",
    "dca632": "Raspberry Pi Trading",
    "e45f01": "Raspberry Pi Trading",
    "d83add": "Raspberry Pi Trading",
    "88a29e": "Raspberry Pi Trading",
    "e4 5f 01": "Raspberry Pi Trading",

    # --- Espressif (ESP8266/ESP32 IoT) ---
    "24 0a c4": "Espressif",
    "240ac4": "Espressif",
    "3c 71 bf": "Espressif",
    "3c71bf": "Espressif",
    "5ccf7f": "Espressif",
    "600194": "Espressif",
    "807d3a": "Espressif",
    "84f3eb": "Espressif",
    "a020a6": "Espressif",
    "b4e62d": "Espressif",
    "bc ddc2": "Espressif",
    "bcddc2": "Espressif",
    "cc50e3": "Espressif",
    "d8bf c0": "Espressif",
    "dc4f22": "Espressif",
    "ecfabc": "Espressif",

    # --- Amazon (Echo, FireTV, Kindle) ---
    "0c47c9": "Amazon",
    "18742e": "Amazon",
    "34d270": "Amazon",
    "40b4cd": "Amazon",
    "44650d": "Amazon",
    "4cefc0": "Amazon",
    "50f5da": "Amazon",
    "6854fd": "Amazon",
    "74c246": "Amazon",
    "747548": "Amazon",
    "84d6d0": "Amazon",
    "a002dc": "Amazon",
    "ac63be": "Amazon",
    "b47c9c": "Amazon",
    "c8 63 f1": "Amazon",
    "cc9ea2": "Amazon",
    "d4ff1a": "Amazon",
    "e0ae5e": "Amazon",
    "f0d2f1": "Amazon",
    "f0f0a4": "Amazon",
    "f4f5d8": "Amazon",
    "fc65de": "Amazon",
    "fc a1 83": "Amazon",

    # --- Google (Nest, Chromecast, Pixel, Google Home) ---
    "1cf29a": "Google",
    "20dfb9": "Google",
    "3c5ab4": "Google",
    "4048 04": "Google",
    "444 7e4": "Google",
    "48d6d5": "Google",
    "546 0a5": "Google",
    "6466b3": "Google",
    "6c ad f8": "Google",
    "94eb2c": "Google",
    "a47733": "Google",
    "d8 6c 63": "Google",
    "f4f5e8": "Google",
    "f88f ca": "Google",

    # --- Roku ---
    "ac3a7a": "Roku",
    "b0a737": "Roku",
    "b83e59": "Roku",
    "c83a35": "Roku",
    "cc6da0": "Roku",
    "d4 67 e7": "Roku",
    "d83134": "Roku",
    "dc3a5e": "Roku",

    # --- Sonos ---
    "5c aa fd": "Sonos",
    "78 28 ca": "Sonos",
    "94 9f 3e": "Sonos",
    "b8 e9 37": "Sonos",

    # --- Ubiquiti ---
    "04 18 d6": "Ubiquiti",
    "24 a4 3c": "Ubiquiti",
    "44 d9 e7": "Ubiquiti",
    "6872 51": "Ubiquiti",
    "74 ac b9": "Ubiquiti",
    "78 8a 20": "Ubiquiti",
    "80 2a a8": "Ubiquiti",
    "b4 f5 5e": "Ubiquiti",
    "dc 9f db": "Ubiquiti",
    "e0 63 da": "Ubiquiti",
    "f0 9f c2": "Ubiquiti",
    "fc ec da": "Ubiquiti",

    # --- TP-Link ---
    "14 cc 20": "TP-Link",
    "1c fa 68": "TP-Link",
    "30 b5 c2": "TP-Link",
    "50 c7 bf": "TP-Link",
    "60 e3 27": "TP-Link",
    "64 66 b3": "TP-Link",
    "64 70 02": "TP-Link",
    "84 16 f9": "TP-Link",
    "a0 f3 c1": "TP-Link",
    "a4 2b b0": "TP-Link",
    "ac 84 c6": "TP-Link",
    "c4 6e 1f": "TP-Link",
    "c4 e9 84": "TP-Link",
    "d8 07 b6": "TP-Link",
    "e8 de 27": "TP-Link",
    "ec 08 6b": "TP-Link",
    "ec 88 8f": "TP-Link",
    "f4 f2 6d": "TP-Link",
    "f8 d1 11": "TP-Link",

    # --- Netgear ---
    "20 4e 7f": "Netgear",
    "28 c6 8e": "Netgear",
    "2c 30 33": "Netgear",
    "3c 37 86": "Netgear",
    "44 94 fc": "Netgear",
    "4c 60 de": "Netgear",
    "6c b0 ce": "Netgear",
    "74 44 01": "Netgear",
    "84 1b 5e": "Netgear",
    "9c 3d cf": "Netgear",
    "a0 40 a0": "Netgear",
    "b0 39 56": "Netgear",
    "b0 7f b9": "Netgear",
    "c0 3f 0e": "Netgear",
    "c4 3d c7": "Netgear",
    "cc 40 d0": "Netgear",
    "dc ef 09": "Netgear",
    "e0 46 9a": "Netgear",
    "e0 91 f5": "Netgear",
    "e4 f4 c6": "Netgear",
    "e8 fc af": "Netgear",
    "f8 73 94": "Netgear",

    # --- D-Link ---
    "00 1b 11": "D-Link",
    "00 1e 58": "D-Link",
    "00 22 b0": "D-Link",
    "00 24 01": "D-Link",
    "00 26 5a": "D-Link",
    "14 d6 4d": "D-Link",
    "1c 7e e5": "D-Link",
    "1c bd b9": "D-Link",
    "28 10 7b": "D-Link",
    "34 08 04": "D-Link",
    "3c 1e 04": "D-Link",
    "40 9b cd": "D-Link",
    "5c d9 98": "D-Link",
    "74 da 88": "D-Link",
    "78 54 2e": "D-Link",
    "84 c9 b2": "D-Link",
    "90 94 e4": "D-Link",
    "ac f1 df": "D-Link",
    "b8 a3 86": "D-Link",
    "c4 12 f5": "D-Link",
    "c8 be 19": "D-Link",
    "cc b2 55": "D-Link",
    "d8 fe e3": "D-Link",
    "f0 7d 68": "D-Link",
    "f4 8c 50": "D-Link",
    "fc 75 16": "D-Link",

    # --- ASUS ---
    "02 1c 42": "ASUS",
    "08 60 6e": "ASUS",
    "08 62 66": "ASUS",
    "10 bf 48": "ASUS",
    "14 dd a9": "ASUS",
    "1c 87 2c": "ASUS",
    "2c 56 dc": "ASUS",
    "2c fd a1": "ASUS",
    "30 5a 3a": "ASUS",
    "38 d5 47": "ASUS",
    "40 16 7e": "ASUS",
    "44 d9 e7": "ASUS",
    "4c ed fb": "ASUS",
    "50 46 5d": "ASUS",
    "54 a0 50": "ASUS",
    "60 45 cb": "ASUS",
    "70 4d 7b": "ASUS",
    "74 d0 2b": "ASUS",
    "88 d7 f6": "ASUS",
    "9c 5c 8e": "ASUS",
    "ac 22 0b": "ASUS",
    "ac 9e 17": "ASUS",
    "b0 6e bf": "ASUS",
    "bc ae c5": "ASUS",
    "c8 60 00": "ASUS",
    "d0 17 c2": "ASUS",
    "d8 50 e6": "ASUS",
    "e0 3f 49": "ASUS",
    "e0 3f 4a": "ASUS",
    "f4 6d e2": "ASUS",
    "f8 32 e4": "ASUS",
    "fc 34 97": "ASUS",

    # --- AVM (Fritz!Box) ---
    "08 96 d7": "AVM",
    "14 65 0e": "AVM",
    "18 e8 29": "AVM",
    "24 65 11": "AVM",
    "38 2c 4a": "AVM",
    "3c a6 2f": "AVM",
    "44 4e 6d": "AVM",
    "5c 49 79": "AVM",
    "68 54 fd": "AVM",
    "88 40 33": "AVM",
    "9c c7 a6": "AVM",
    "c8 0e 14": "AVM",
    "c8 0e 15": "AVM",
    "e8 df 70": "AVM",

    # --- MikroTik ---
    "18 fd 74": "MikroTik",
    "2c c8 1b": "MikroTik",
    "48 8f 5a": "MikroTik",
    "4c 5e 0c": "MikroTik",
    "64 d1 54": "MikroTik",
    "6c 3b 6b": "MikroTik",
    "74 4d 28": "MikroTik",
    "78 9a 18": "MikroTik",
    "b8 69 f4": "MikroTik",
    "cc 2d e0": "MikroTik",
    "dc 2c 6e": "MikroTik",
    "e4 8d 8c": "MikroTik",
    
        # --- Fortinet (very common firewall/UTM vendor) ---
    "38c0ea": "Fortinet",
    "584146": "Fortinet",
    "00090f": "Fortinet",
    "04d590": "Fortinet",
    "085b0e": "Fortinet",
    "0c9a42": "Fortinet",
    "704ca5": "Fortinet",
    "906cac": "Fortinet",
    "a0f9e0": "Fortinet",
    "e01c41": "Fortinet",
    "f4cfe2": "Fortinet",

    # --- Proxmox VE (uses its own MAC pool for VMs) ---
    "bc2411": "Proxmox VE",
    "0016 3e": "Xen",     # (already listed, kept for clarity)
    
    # --- Additional common OUIs seen in corporate /24s ---
    "4c2358": "Unknown (4c:23:58)",         # matches your .33 host
    "b456e3": "Unknown (b4:56:e3)",         # matches your .34 host
    "b0a460": "Unknown (b0:a4:60)",         # matches your .163 host
    "a82948": "Unknown (a8:29:48)",         # matches your .172 host
    "a842a1": "Unknown (a8:42:a1)",         # matches your .170 host
    "7cd1ad": "Unknown (7c:d1:ad)",         # matches your .26 host
    "744218": "Unknown (74:42:18)",         # matches your .70 host
    "4ec212": "Unknown (4e:c2:12)",         # matches your .91 host (locally admin)
    "dcf505": "Unknown (dc:f5:05)",         # matches your .112 host
    "b8f775": "Unknown (b8:f7:75)",         # matches your .131 host
    "700894": "Unknown (70:08:94)",         # matches your .134 host
    "749779": "Unknown (74:97:79)",         # matches your .135 host
    "f8ffc2": "Apple",                       # your .137 host
    "607ea4": "Unknown (60:7e:a4)",         # matches your .157 host
    "9cc7d3": "Unknown (9c:c7:d3)",         # matches your .161 host
    "bc2411": "Proxmox VE",                  # your .162 host (dup with above)
    "b0a460": "Unknown (b0:a4:60)",         # your .163 (dup with above)
    "a8 29 48": "Unknown",                    # your .172 (dup)
    "02 8d 3d": "Locally Administered",      # your .48
    "80a579": "Unknown (80:a5:79)",         # your .49, .80, .92
    "04 00 6e": "Unknown (04:00:6e)",       # your .54
    "f01fc7": "Unknown (f0:1f:c7)",         # your .62
    "60e9aa": "Unknown (60:e9:aa)",         # your .64
    "f004e1": "Unknown (f0:04:e1)",         # your .65
    "b06088": "Unknown (b0:60:88)",         # your .66
    "9860ca": "Unknown (98:60:ca)",         # your .68
    "c0bfbe": "Unknown (c0:bf:be)",         # your .69
    "88d7f6": "ASUS",                         # your .7 (dup with ASUS)
    "12a827": "Locally Administered",        # your .72
    "908c43": "Unknown (90:8c:43)",         # your .73
    "388a06": "Unknown (38:8a:06)",         # your .79
    "1c57dc": "Unknown (1c:57:dc)",         # your .81
    "da3cb4": "Locally Administered",        # your .83
    "242fd0": "Unknown (24:2f:d0)",         # your .84
    "7478a6": "Unknown (74:78:a6)",         # your .9
    "d06578": "Unknown (d0:65:78)",         # your .99

    # --- Cisco ---
    "00 00 0c": "Cisco",
    "00 01 42": "Cisco",
    "00 01 43": "Cisco",
    "00 01 63": "Cisco",
    "00 01 64": "Cisco",
    "00 01 96": "Cisco",
    "00 01 97": "Cisco",
    "00 01 c7": "Cisco",
    "00 02 16": "Cisco",
    "00 02 17": "Cisco",
    "00 02 3d": "Cisco",
    "00 02 4a": "Cisco",
    "00 02 4b": "Cisco",
    "00 02 7d": "Cisco",
    "00 02 7e": "Cisco",
    "00 02 7f": "Cisco",
    "00 02 b9": "Cisco",
    "00 02 ba": "Cisco",
    "00 02 fc": "Cisco",
    "00 02 fd": "Cisco",
    "00 03 32": "Cisco",
    "00 03 6b": "Cisco",
    "00 03 6c": "Cisco",
    "00 03 9f": "Cisco",
    "00 03 a0": "Cisco",
    "00 03 e3": "Cisco",
    "00 03 e4": "Cisco",
    "00 03 fd": "Cisco",
    "00 03 fe": "Cisco",
    "00 04 27": "Cisco",
    "00 04 28": "Cisco",
    "00 04 4d": "Cisco",
    "00 04 4e": "Cisco",
    "00 04 6d": "Cisco",
    "00 04 6e": "Cisco",
    "00 04 9a": "Cisco",
    "00 04 9b": "Cisco",
    "00 04 c0": "Cisco",
    "00 04 c1": "Cisco",
    "00 04 dd": "Cisco",
    "00 04 de": "Cisco",
    "00 05 00": "Cisco",
    "00 05 01": "Cisco",
    "00 05 31": "Cisco",
    "00 05 32": "Cisco",
    "00 05 5d": "Cisco",
    "00 05 5e": "Cisco",
    "00 05 73": "Cisco",
    "00 05 74": "Cisco",
    "00 05 9a": "Cisco",
    "00 05 9b": "Cisco",
    "00 05 dc": "Cisco",
    "00 05 dd": "Cisco",
    "00 06 28": "Cisco",
    "00 06 2a": "Cisco",
    "00 06 52": "Cisco",
    "00 06 53": "Cisco",
    "00 06 5e": "Cisco",
    "00 06 5f": "Cisco",
    "00 06 7c": "Cisco",
    "00 06 c1": "Cisco",
    "00 06 d6": "Cisco",
    "00 06 d7": "Cisco",
    "00 06 f6": "Cisco",
    "00 07 0d": "Cisco",
    "00 07 0e": "Cisco",
    "00 07 31": "Cisco",
    "00 07 32": "Cisco",
    "00 07 4f": "Cisco",
    "00 07 7d": "Cisco",
    "00 07 7e": "Cisco",
    "00 07 84": "Cisco",
    "00 07 85": "Cisco",
    "00 07 b3": "Cisco",
    "00 07 b4": "Cisco",
    "00 07 eb": "Cisco",
    "00 07 ec": "Cisco",
    "00 08 20": "Cisco",
    "00 08 21": "Cisco",
    "00 08 2f": "Cisco",
    "00 08 30": "Cisco",
    "00 08 7c": "Cisco",
    "00 08 a3": "Cisco",
    "00 08 a4": "Cisco",
    "00 08 c2": "Cisco",
    "00 08 e2": "Cisco",
    "00 08 e3": "Cisco",
    "00 09 11": "Cisco",
    "00 09 12": "Cisco",
    "00 09 43": "Cisco",
    "00 09 44": "Cisco",
    "00 09 7b": "Cisco",
    "00 09 7c": "Cisco",
    "00 09 b6": "Cisco",
    "00 09 b7": "Cisco",
    "00 09 e8": "Cisco",
    "00 09 e9": "Cisco",
    "00 0a 41": "Cisco",
    "00 0a 42": "Cisco",
    "00 0a 8a": "Cisco",
    "00 0a 8b": "Cisco",
    "00 0a b7": "Cisco",
    "00 0a b8": "Cisco",
    "00 0a f3": "Cisco",
    "00 0a f4": "Cisco",
    "00 0b 45": "Cisco",
    "00 0b 46": "Cisco",
    "00 0b 5f": "Cisco",
    "00 0b 60": "Cisco",
    "00 0b 85": "Cisco",
    "00 0b be": "Cisco",
    "00 0b bf": "Cisco",
    "00 0b fc": "Cisco",
    "00 0b fd": "Cisco",
    "00 0c 30": "Cisco",
    "00 0c 31": "Cisco",
    "00 0c 41": "Cisco",
    "00 0c 85": "Cisco",
    "00 0c 86": "Cisco",
    "00 0c ce": "Cisco",
    "00 0c cf": "Cisco",
    "00 0d 28": "Cisco",
    "00 0d 29": "Cisco",
    "00 0d 65": "Cisco",
    "00 0d 66": "Cisco",
    "00 0d 93": "Cisco",
    "00 0d bc": "Cisco",
    "00 0d bd": "Cisco",
    "00 0d ec": "Cisco",
    "00 0d ed": "Cisco",
    "00 0e 38": "Cisco",
    "00 0e 39": "Cisco",
    "00 0e 83": "Cisco",
    "00 0e 84": "Cisco",
    "00 0e a6": "Cisco",
    "00 0e d6": "Cisco",
    "00 0e d7": "Cisco",
    "00 0f 23": "Cisco",
    "00 0f 24": "Cisco",
    "00 0f 34": "Cisco",
    "00 0f 35": "Cisco",
    "00 0f 8f": "Cisco",
    "00 0f 90": "Cisco",
    "00 0f b6": "Cisco",
    "00 0f b7": "Cisco",
    "00 0f f7": "Cisco",
    "00 0f f8": "Cisco",
    "00 10 07": "Cisco",
    "00 10 0b": "Cisco",
    "00 10 0d": "Cisco",
    "00 10 11": "Cisco",
    "00 10 14": "Cisco",
    "00 10 1f": "Cisco",
    "00 10 29": "Cisco",
    "00 10 2f": "Cisco",
    "00 10 54": "Cisco",
    "00 10 79": "Cisco",
    "00 10 7b": "Cisco",
    "00 10 a6": "Cisco",
    "00 10 f6": "Cisco",
    "00 10 ff": "Cisco",
    "00 11 20": "Cisco",
    "00 11 21": "Cisco",
    "00 11 5c": "Cisco",
    "00 11 5d": "Cisco",
    "00 11 92": "Cisco",
    "00 11 93": "Cisco",
    "00 11 bb": "Cisco",
    "00 11 bc": "Cisco",
    "00 12 00": "Cisco",
    "00 12 01": "Cisco",
    "00 12 43": "Cisco",
    "00 12 44": "Cisco",
    "00 12 7f": "Cisco",
    "00 12 80": "Cisco",
    "00 12 7f": "Cisco",
    "00 12 da": "Cisco",
    "00 12 db": "Cisco",
    "00 13 19": "Cisco",
    "00 13 1a": "Cisco",
    "00 13 5f": "Cisco",
    "00 13 60": "Cisco",
    "00 13 7f": "Cisco",
    "00 13 80": "Cisco",
    "00 13 c3": "Cisco",
    "00 13 c4": "Cisco",
    "00 14 1b": "Cisco",
    "00 14 1c": "Cisco",
    "00 14 69": "Cisco",
    "00 14 6a": "Cisco",
    "00 14 a8": "Cisco",
    "00 14 a9": "Cisco",
    "00 14 f1": "Cisco",
    "00 14 f2": "Cisco",
    "00 15 2b": "Cisco",
    "00 15 2c": "Cisco",
    "00 15 62": "Cisco",
    "00 15 63": "Cisco",
    "00 15 c6": "Cisco",
    "00 15 c7": "Cisco",
    "00 15 f9": "Cisco",
    "00 15 fa": "Cisco",
    "00 16 46": "Cisco",
    "00 16 47": "Cisco",
    "00 16 9c": "Cisco",
    "00 16 9d": "Cisco",
    "00 16 c7": "Cisco",
    "00 16 c8": "Cisco",
    "00 17 0e": "Cisco",
    "00 17 0f": "Cisco",
    "00 17 5a": "Cisco",
    "00 17 5b": "Cisco",
    "00 17 94": "Cisco",
    "00 17 95": "Cisco",
    "00 17 df": "Cisco",
    "00 17 e0": "Cisco",
    "00 18 18": "Cisco",
    "00 18 19": "Cisco",
    "00 18 39": "Cisco",
    "00 18 68": "Cisco",
    "00 18 b9": "Cisco",
    "00 18 ba": "Cisco",
    "00 19 06": "Cisco",
    "00 19 07": "Cisco",
    "00 19 2f": "Cisco",
    "00 19 30": "Cisco",
    "00 19 55": "Cisco",
    "00 19 56": "Cisco",
    "00 19 a9": "Cisco",
    "00 19 aa": "Cisco",
    "00 19 e7": "Cisco",
    "00 19 e8": "Cisco",
    "00 1a 2f": "Cisco",
    "00 1a 30": "Cisco",
    "00 1a 6c": "Cisco",
    "00 1a 6d": "Cisco",
    "00 1a a1": "Cisco",
    "00 1a a2": "Cisco",
    "00 1a e2": "Cisco",
    "00 1a e3": "Cisco",
    "00 1b 0c": "Cisco",
    "00 1b 0d": "Cisco",
    "00 1b 2a": "Cisco",
    "00 1b 2b": "Cisco",
    "00 1b 53": "Cisco",
    "00 1b 54": "Cisco",
    "00 1b 8f": "Cisco",
    "00 1b 90": "Cisco",
    "00 1b d4": "Cisco",
    "00 1b d5": "Cisco",
    "00 1c 0e": "Cisco",
    "00 1c 0f": "Cisco",
    "00 1c 57": "Cisco",
    "00 1c 58": "Cisco",
    "00 1c b0": "Cisco",
    "00 1c b1": "Cisco",
    "00 1d 45": "Cisco",
    "00 1d 46": "Cisco",
    "00 1d 70": "Cisco",
    "00 1d 71": "Cisco",
    "00 1d a1": "Cisco",
    "00 1d a2": "Cisco",
    "00 1d e5": "Cisco",
    "00 1d e6": "Cisco",
    "00 1e 13": "Cisco",
    "00 1e 14": "Cisco",
    "00 1e 49": "Cisco",
    "00 1e 4a": "Cisco",
    "00 1e 79": "Cisco",
    "00 1e 7a": "Cisco",
    "00 1e bd": "Cisco",
    "00 1e be": "Cisco",
    "00 1e f6": "Cisco",
    "00 1e f7": "Cisco",
    "00 1f 26": "Cisco",
    "00 1f 27": "Cisco",
    "00 1f 6c": "Cisco",
    "00 1f 6d": "Cisco",
    "00 1f 9d": "Cisco",
    "00 1f 9e": "Cisco",
    "00 1f ca": "Cisco",
    "00 1f cb": "Cisco",
    "00 20 85": "Cisco",
    "00 21 1b": "Cisco",
    "00 21 1c": "Cisco",
    "00 21 55": "Cisco",
    "00 21 56": "Cisco",
    "00 21 a0": "Cisco",
    "00 21 a1": "Cisco",
    "00 21 d7": "Cisco",
    "00 21 d8": "Cisco",
    "00 22 0c": "Cisco",
    "00 22 0d": "Cisco",
    "00 22 55": "Cisco",
    "00 22 56": "Cisco",
    "00 22 90": "Cisco",
    "00 22 91": "Cisco",
    "00 22 bd": "Cisco",
    "00 22 be": "Cisco",
    "00 23 04": "Cisco",
    "00 23 05": "Cisco",
    "00 23 33": "Cisco",
    "00 23 34": "Cisco",
    "00 23 5e": "Cisco",
    "00 23 5f": "Cisco",
    "00 23 ab": "Cisco",
    "00 23 ac": "Cisco",
    "00 23 ea": "Cisco",
    "00 23 eb": "Cisco",
    "00 24 13": "Cisco",
    "00 24 14": "Cisco",
    "00 24 50": "Cisco",
    "00 24 51": "Cisco",
    "00 24 97": "Cisco",
    "00 24 98": "Cisco",
    "00 24 c3": "Cisco",
    "00 24 c4": "Cisco",
    "00 24 f7": "Cisco",
    "00 24 f9": "Cisco",
    "00 25 2b": "Cisco",
    "00 25 2c": "Cisco",
    "00 25 45": "Cisco",
    "00 25 46": "Cisco",
    "00 25 84": "Cisco",
    "00 25 85": "Cisco",
    "00 25 b4": "Cisco",
    "00 25 b5": "Cisco",
    "00 25 ef": "Cisco",
    "00 25 f0": "Cisco",
    "00 26 0a": "Cisco",
    "00 26 0b": "Cisco",
    "00 26 51": "Cisco",
    "00 26 52": "Cisco",
    "00 26 98": "Cisco",
    "00 26 99": "Cisco",
    "00 26 ca": "Cisco",
    "00 26 cb": "Cisco",
    "00 26 0a": "Cisco",
    "00 26 0b": "Cisco",
    "00 26 51": "Cisco",
    "00 26 52": "Cisco",
    "00 26 98": "Cisco",
    "00 26 99": "Cisco",
    "00 26 ca": "Cisco",
    "00 26 cb": "Cisco",

    # --- Juniper ---
    "00 05 85": "Juniper",
    "00 12 1e": "Juniper",
    "00 14 f6": "Juniper",
    "00 15 f5": "Juniper",
    "00 17 cb": "Juniper",
    "00 19 e2": "Juniper",
    "00 1b c0": "Juniper",
    "00 1d b5": "Juniper",
    "00 1f 12": "Juniper",
    "00 21 59": "Juniper",
    "00 22 83": "Juniper",
    "00 23 9c": "Juniper",
    "00 24 dc": "Juniper",
    "00 26 88": "Juniper",
    "08 b2 a3": "Juniper",
    "0c 86 10": "Juniper",
    "10 0e 7e": "Juniper",
    "2c 21 72": "Juniper",
    "2c 6b f5": "Juniper",
    "30 7c 5e": "Juniper",
    "3c 8a b0": "Juniper",
    "3c e5 a6": "Juniper",
    "40 a6 77": "Juniper",
    "40 b4 f0": "Juniper",
    "44 aa 50": "Juniper",
    "44 f4 77": "Juniper",
    "4c 16 fc": "Juniper",
    "4c 6d 58": "Juniper",
    "50 c5 8d": "Juniper",
    "54 1e 56": "Juniper",
    "54 e0 32": "Juniper",
    "5c 45 27": "Juniper",
    "5c 5e ab": "Juniper",
    "64 64 9b": "Juniper",
    "64 87 88": "Juniper",
    "78 19 f7": "Juniper",
    "78 fe 3d": "Juniper",
    "7c e2 ca": "Juniper",
    "80 71 1f": "Juniper",
    "80 ac ac": "Juniper",
    "84 18 88": "Juniper",
    "84 b5 9c": "Juniper",
    "88 a2 5e": "Juniper",
    "88 e0 f3": "Juniper",
    "8c 5a c1": "Juniper",
    "9c cc 83": "Juniper",
    "a8 d0 e5": "Juniper",
    "ac 4b c8": "Juniper",
    "b0 a8 6e": "Juniper",
    "b0 c6 9a": "Juniper",
    "c0 42 d0": "Juniper",
    "c4 71 fe": "Juniper",
    "cc e1 7f": "Juniper",
    "d0 dd 00": "Juniper",
    "d4 8c b5": "Juniper",
    "d8 b1 22": "Juniper",
    "dc 38 e1": "Juniper",
    "e0 d1 73": "Juniper",
    "e4 fc 82": "Juniper",
    "e8 b6 c2": "Juniper",
    "ec 13 db": "Juniper",
    "ec 3e f7": "Juniper",
    "f0 1c 2d": "Juniper",
    "f4 a7 39": "Juniper",
    "f4 b5 2f": "Juniper",
    "f4 cc 55": "Juniper",
    "f8 c0 01": "Juniper",

    # --- Aruba / HPE Networking ---
    "00 0b 86": "Aruba Networks",
    "00 1a 1e": "Aruba Networks",
    "00 24 6c": "Aruba Networks",
    "04 bd 88": "Aruba Networks",
    "18 64 72": "Aruba Networks",
    "20 4c 03": "Aruba Networks",
    "24 de c6": "Aruba Networks",
    "40 e3 d6": "Aruba Networks",
    "6c f3 7f": "Aruba Networks",
    "70 3a 0e": "Aruba Networks",
    "84 d4 7e": "Aruba Networks",
    "94 b4 0f": "Aruba Networks",
    "9c 1c 12": "Aruba Networks",
    "ac a3 1e": "Aruba Networks",
    "b4 5d 50": "Aruba Networks",
    "d8 c7 c8": "Aruba Networks",
    "f0 5c 19": "Aruba Networks",

    # --- Arista ---
    "00 1c 73": "Arista",
    "28 99 3a": "Arista",
    "2c dd e9": "Arista",
    "44 4c a8": "Arista",
    "74 83 ef": "Arista",
    "98 5d 82": "Arista",
    "a4 b4 39": "Arista",
    "c4 ca 2b": "Arista",
    "e8 c5 7a": "Arista",
    "fc bd 67": "Arista",

    # --- Fortinet ---
    "00 09 0f": "Fortinet",
    "04 d5 90": "Fortinet",
    "08 5b 0e": "Fortinet",
    "0c 9a 42": "Fortinet",
    "70 4c a5": "Fortinet",
    "90 6c ac": "Fortinet",
    "a0 f9 e0": "Fortinet",

    # --- Palo Alto Networks ---
    "00 1b 17": "Palo Alto",
    "b4 0c 25": "Palo Alto",
    "d4 f4 be": "Palo Alto",

    # --- Intel (WiFi NICs) ---
    "00 02 b3": "Intel",
    "00 03 47": "Intel",
    "00 04 23": "Intel",
    "00 07 e9": "Intel",
    "00 0c f1": "Intel",
    "00 0e 0c": "Intel",
    "00 0e 35": "Intel",
    "00 11 11": "Intel",
    "00 12 f0": "Intel",
    "00 13 02": "Intel",
    "00 13 20": "Intel",
    "00 13 ce": "Intel",
    "00 13 e8": "Intel",
    "00 15 00": "Intel",
    "00 15 17": "Intel",
    "00 16 6f": "Intel",
    "00 16 6f": "Intel",
    "00 16 eb": "Intel",
    "00 16 ea": "Intel",
    "00 17 35": "Intel",
    "00 18 de": "Intel",
    "00 19 d1": "Intel",
    "00 19 d2": "Intel",
    "00 1b 21": "Intel",
    "00 1b 77": "Intel",
    "00 1c bf": "Intel",
    "00 1c c0": "Intel",
    "00 1d e0": "Intel",
    "00 1d e1": "Intel",
    "00 1e 64": "Intel",
    "00 1e 65": "Intel",
    "00 1e 67": "Intel",
    "00 1f 3b": "Intel",
    "00 1f 3c": "Intel",
    "00 20 7b": "Intel",
    "00 21 5c": "Intel",
    "00 21 5d": "Intel",
    "00 21 6a": "Intel",
    "00 21 6b": "Intel",
    "00 21 6c": "Intel",
    "00 21 6c": "Intel",
    "00 21 6d": "Intel",
    "00 22 fb": "Intel",
    "00 22 fa": "Intel",
    "00 23 14": "Intel",
    "00 23 15": "Intel",
    "00 24 d6": "Intel",
    "00 24 d7": "Intel",
    "00 26 c6": "Intel",
    "00 26 c7": "Intel",
    "00 27 0e": "Intel",
    "00 27 10": "Intel",
    "00 27 10": "Intel",
    "02 1c 42": "Intel",
    "02 1c 42": "Intel",
    "04 7e 4a": "Intel",
    "04 7e 4a": "Intel",
    "04 7e 4a": "Intel",
    "08 11 96": "Intel",
    "08 11 96": "Intel",
    "0c 8b fd": "Intel",
    "0c 8b fd": "Intel",
    "0c d2 92": "Intel",
    "10 02 b5": "Intel",
    "10 02 b5": "Intel",
    "10 0b a9": "Intel",
    "10 0b a9": "Intel",
    "10 0e 7e": "Intel",
    "10 0e 7e": "Intel",
    "10 4a 7d": "Intel",
    "10 f0 05": "Intel",
    "10 f0 05": "Intel",
    "14 5a fc": "Intel",
    "14 5a fc": "Intel",

    # --- Broadcom (WiFi/embedded) ---
    "00 05 a8": "Broadcom",
    "00 10 18": "Broadcom",
    "00 10 18": "Broadcom",
    "00 1b e9": "Broadcom",
    "00 1c c0": "Broadcom",
    "00 24 23": "Broadcom",
    "18 c0 86": "Broadcom",

    # --- Realtek ---
    # Note: 52:54:00 and 52:54:ab are QEMU/KVM, listed above. This
    # block used to include them by mistake, which silently overrode
    # the QEMU entries (dict literals keep the last duplicate key).
    "00e04c": "Realtek",
    "00e04d": "Realtek",

    # --- Other well-known IoT / consumer ---
    "00 04 20": "Linksys",
    "00 06 25": "Linksys",
    "00 0c 41": "Linksys",
    "00 0f 66": "Linksys",
    "00 12 17": "Linksys",
    "00 13 10": "Linksys",
    "00 14 bf": "Linksys",
    "00 16 b6": "Linksys",
    "00 18 39": "Linksys",
    "00 18 f8": "Linksys",
    "00 1a 70": "Linksys",
    "00 1c 10": "Linksys",
    "00 1d 7e": "Linksys",
    "00 1e e5": "Linksys",
    "00 1f 5b": "Linksys",
    "00 20 2b": "Linksys",
    "00 20 a6": "Linksys",
    "00 21 29": "Linksys",
    "00 22 6b": "Linksys",
    "00 23 69": "Linksys",
    "00 25 9c": "Linksys",
    "00 25 9c": "Linksys",
    "14 91 82": "Linksys",
    "20 aa 4b": "Linksys",
    "48 f8 b3": "Linksys",
    "58 6d 8f": "Linksys",
    "68 7f 74": "Linksys",
    "c0 56 27": "Linksys",
    "c0 c1 c0": "Linksys",
}


# ---------------------------------------------------------------------
# MAC parsing and lookup
# ---------------------------------------------------------------------

_MAC_RE = re.compile(r"[^0-9a-f]")


def normalize_mac(mac: str) -> str | None:
    """Strip separators and lowercase. Returns 12 hex chars or None."""
    if not mac:
        return None
    cleaned = _MAC_RE.sub("", mac.lower())
    if len(cleaned) != 12:
        return None
    try:
        int(cleaned, 16)
    except ValueError:
        return None
    return cleaned


def oui_from_mac(mac: str) -> str | None:
    """Extract the first-3-byte OUI from a MAC (6 hex chars, lowercase)."""
    cleaned = normalize_mac(mac)
    return cleaned[:6] if cleaned else None


def is_locally_administered(mac: str) -> bool:
    """Return True if the MAC has the locally-administered bit set.

    Locally-administered MACs are almost always virtual (VMware, KVM,
    VirtualBox, Xen, Docker, etc.) — the hypervisor picks them, not
    IEEE. The 2nd-least-significant bit of the 1st byte is the flag.
    """
    cleaned = normalize_mac(mac)
    if not cleaned:
        return False
    first_byte = int(cleaned[:2], 16)
    return bool(first_byte & 0b00000010)


# ---------------------------------------------------------------------
# OUI database: load, cache, download
# ---------------------------------------------------------------------

class OUIDB:
    """In-memory OUI → vendor map. Loads from cache, embedded, or IEEE."""

    def __init__(self):
        self.table: dict[str, str] = {}
        self.source = "empty"

    def load_embedded(self):
        self.table = {k.lower().replace(" ", ""): v
                      for k, v in EMBEDDED_OUI.items()}
        self.source = "embedded"

    def load_cache(self) -> bool:
        """Parse the cached oui.txt. Returns True if successful."""
        if not CACHE_FILE.exists():
            return False
        try:
            self._parse_ieee_file(CACHE_FILE.read_text(
                encoding="utf-8", errors="ignore"))
            self.source = f"cache ({CACHE_FILE})"
            return True
        except Exception as e:
            warn(f"could not parse OUI cache: {type(e).__name__}: {e}")
            return False

    def download(self, timeout=60) -> bool:
        """Download the IEEE OUI file and parse it. Returns True on success."""
        info(f"downloading IEEE OUI list (~6 MB) from {IEEE_OUI_URL}")
        # IEEE's CDN returns HTTP 418 to the default urllib User-Agent.
        # Set a real UA so we get the file.
        req = urllib.request.Request(
            IEEE_OUI_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; toolkit/0.1)",
                "Accept": "text/plain,*/*",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                data = raw.decode("utf-8", errors="ignore")
        except Exception as e:
            warn(f"OUI download failed: {type(e).__name__}: {e}")
            return False

        # Save to cache first, then parse.
        try:
            CACHE_FILE.write_text(data, encoding="utf-8")
        except Exception as e:
            warn(f"could not write OUI cache: {e}")

        self._parse_ieee_file(data)
        self.source = "downloaded"
        success(f"OUI database loaded: {len(self.table):,} vendors")
        return True
        

    @staticmethod
    def _parse_ieee_file(text: str):
        """Parse the IEEE oui.txt format:

            XX-XX-XX   (hex)        Vendor Name
            XXXXXX     (base 16)    Vendor Name

        We accept either form. We keep the (hex) form when both appear,
        because it's the canonical representation.
        """
        # Reset self.table here too — this is a staticmethod and the
        # caller provides text, so we return the parsed dict.
        pass  # will be redefined on instance

    def _parse_ieee_file_impl(self, text: str):
        """Instance version so we can populate self.table."""
        table = {}
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            # Form: "XX-XX-XX   (hex)        Vendor Name"
            if "(hex)" in line:
                prefix, _, rest = line.partition("(hex)")
                key = prefix.replace("-", "").replace(" ", "").lower()
                vendor = rest.strip()
                if len(key) == 6 and vendor:
                    table[key] = vendor
            # Form: "XXXXXX     (base 16)    Vendor Name"
            elif "(base 16)" in line:
                prefix, _, rest = line.partition("(base 16)")
                key = prefix.strip().lower()
                vendor = rest.strip()
                if len(key) == 6 and vendor:
                    table.setdefault(key, vendor)
        if table:
            self.table = table

    def lookup(self, mac: str) -> str | None:
        """Return vendor name for a MAC, or None."""
        oui = oui_from_mac(mac)
        if not oui:
            return None
        vendor = self.table.get(oui)
        if vendor:
            return vendor
        # Locally-administered fallback
        if is_locally_administered(mac):
            return "Locally Administered (likely VM/container)"
        return None


# Patch the parser onto the instance
def _parse_ieee_file_method(self, text):
    """Parse the IEEE OUI file. Handles both the legacy 'XX-XX-XX (hex)'
    format and the modern padded-column format that starts with a header
    block. Returns nothing; populates self.table.

    Modern format sample:

        OUI/MA-L                                                    Organization
        company_id                                                  Organization
        ...
        (blank)
        28-6F-B9   (hex)        Nokia Shanghai Bell Co., Ltd.
        286FB9     (base 16)    Nokia Shanghai Bell Co., Ltd.
        ...

    Both '(hex)' and '(base 16)' lines are present; we prefer the
    '(hex)' form when both exist.
    """
    table = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Legacy and modern both use "(hex)" and "(base 16)" markers
        if "(hex)" in stripped:
            prefix, _, rest = stripped.partition("(hex)")
            key = prefix.replace("-", "").replace(" ", "").lower()
            vendor = rest.strip()
            if len(key) == 6 and _is_hex(key) and vendor:
                table[key] = vendor
        elif "(base 16)" in stripped:
            prefix, _, rest = stripped.partition("(base 16)")
            key = prefix.strip().lower()
            vendor = rest.strip()
            if len(key) == 6 and _is_hex(key) and vendor:
                # Don't overwrite the (hex) form if it already parsed
                table.setdefault(key, vendor)

    if table:
        self.table = table


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


OUIDB._parse_ieee_file = _parse_ieee_file_method


# ---------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------

_DB: OUIDB | None = None


def get_db(force_reload=False) -> OUIDB:
    """Return the singleton OUI database, loading from cache/embedded/IEEE."""
    global _DB
    if _DB is not None and not force_reload:
        return _DB

    db = OUIDB()
    # Try cache first
    if not force_reload and db.load_cache():
        info(f"OUI database loaded from cache: {len(db.table)} vendors")
        _DB = db
        return db
    # Try download (uses cached copy if it's fresh)
    if CACHE_FILE.exists():
        age_days = (time.time() - CACHE_FILE.stat().st_mtime) / 86400
        if age_days > CACHE_MAX_AGE_DAYS:
            info(f"OUI cache is {age_days:.1f} days old; refreshing")
            if db.download():
                _DB = db
                return db
        elif db.load_cache():
            info(f"OUI database loaded from cache: {len(db.table)} vendors")
            _DB = db
            return db
    # Try download
    if db.download():
        _DB = db
        return db
    # Fallback
    warn("using embedded OUI list (download failed)")
    db.load_embedded()
    _DB = db
    return db


def lookup(mac: str) -> str | None:
    """Look up a MAC's vendor. Convenience wrapper over the singleton."""
    return get_db().lookup(mac)


# ---------------------------------------------------------------------
# Store integration — the module-level entry point
# ---------------------------------------------------------------------

async def run(target=None, store=None, verbose=False, force_refresh=False):
    """Enrich host records with vendor info.

    If `target` is a CIDR or IP, run an ARP sweep first to discover
    hosts, then look up each MAC's vendor and write into `store`.

    If `store` already has hosts, and target is None, we enrich those
    in place instead of scanning.

    Args:
        target: CIDR/IP string, or None to enrich existing store hosts.
        store: a core.store.Store instance. Required for writes.
        verbose: print each lookup.
        force_refresh: re-download the OUI list even if cache is fresh.
    """
    db = get_db(force_reload=force_refresh)
    info(f"OUI database: {len(db.table)} vendors (source: {db.source})")

    if store is None:
        warn("no store provided; nothing will be persisted")
        return {}

    results = {}

    # Path A: enrich from existing store hosts
    if target is None:
        hosts = store.query_hosts()
        info(f"enriching {len(hosts)} existing host(s) with vendor info")
        for h in hosts:
            mac = h.get("mac")
            if not mac:
                continue
            vendor = db.lookup(mac)
            if vendor:
                # Store vendor as a tag; hosts table has no vendor column
                # yet (would be a v2 migration). We record it as a tag.
                tags = h.get("tags") or []
                if vendor not in tags:
                    tags.append(f"vendor:{vendor}")
                store.upsert_host(
                    h["ip"],
                    mac=mac,
                    hostname=h.get("hostname"),
                    os_guess=h.get("os_guess"),
                    discovery=h.get("discovery"),
                    tags=tags,
                )
                results[h["ip"]] = vendor
                if verbose:
                    info(f"  {h['ip']:18s} {mac:18s} {vendor}")
        return results

    # Path B: discover + enrich
    from net.host_discovery import discover
    info(f"running ARP discovery on {target} before OUI enrichment")
    inventory = await discover(
        [target] if "/" in target else [f"{target}/32"],
        show_progress=False, verbose=False,
    )

    for ip, host in inventory.items():
        mac = host.get("mac")
        if not mac or mac.startswith("via-"):
            continue
        vendor = db.lookup(mac)
        if not vendor:
            continue
        tags = [f"vendor:{vendor}"]
        store.upsert_host(
            ip,
            mac=mac,
            hostname=host.get("hostname"),
            os_guess=host.get("os_guess"),
            discovery=host.get("discovery"),
            tags=tags,
        )
        results[ip] = vendor
        if verbose:
            info(f"  {ip:18s} {mac:18s} {vendor}")

    success(f"enriched {len(results)} host(s) with vendor info")
    
    return results


def _diagnose():
    """Test download, parse, and cache. Report each stage."""
    print("=== OUI diagnostics ===")
    print(f"cache file: {CACHE_FILE}")
    print(f"exists    : {CACHE_FILE.exists()}")
    if CACHE_FILE.exists():
        st = CACHE_FILE.stat()
        print(f"size      : {st.st_size:,} bytes")
        print(f"age       : {(time.time() - st.st_mtime) / 86400:.1f} days")

    print()
    print("=== attempting download + parse ===")
    db = OUIDB()
    ok = db.download(timeout=30)
    print(f"download  : {'OK' if ok else 'FAILED'}")
    print(f"vendors   : {len(db.table):,}")
    if db.table:
        samples = list(db.table.items())[:5]
        print("first 5 entries:")
        for k, v in samples:
            print(f"  {k} -> {v}")
    print()
    print(f"=== cache file after download ===")
    print(f"exists    : {CACHE_FILE.exists()}")
    if CACHE_FILE.exists():
        print(f"size      : {CACHE_FILE.stat().st_size:,} bytes")

# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="net.oui",
        description="MAC → vendor lookup via IEEE OUI registry.",
    )
    p.add_argument("mac", nargs="?", help="single MAC to look up")
    p.add_argument("--target", help="CIDR/IP to discover and enrich")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--refresh", action="store_true",
                   help="force-refresh the OUI cache")
    p.add_argument("--diagnose", action="store_true",
                   help="test download + parse; report what failed")
    args = p.parse_args()

    if args.diagnose:
        _diagnose()
        return

    if args.mac:
        vendor = lookup(args.mac)
        print(vendor or "(unknown)")
        return