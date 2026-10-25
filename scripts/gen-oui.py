"""Génère src-tauri/data/oui.tsv (préfixe MAC 24 bits -> fabricant court) depuis le CSV de l'IEEE.

Usage :
    curl -o oui.csv https://standards-oui.ieee.org/oui/oui.csv
    python scripts/gen-oui.py oui.csv src-tauri/data/oui.tsv
"""
import csv
import re
import sys

src, dst = sys.argv[1], sys.argv[2]

BRANDS = [
    ("apple", "Apple"), ("samsung", "Samsung"), ("huawei", "Huawei"), ("hon hai", "Foxconn"),
    ("sagemcom", "Sagemcom"), ("freebox", "Freebox"), ("espressif", "Espressif"), ("raspberry pi", "Raspberry Pi"),
    ("tp-link", "TP-Link"), ("tp link", "TP-Link"), ("amazon", "Amazon"), ("google", "Google"), ("xiaomi", "Xiaomi"),
    ("intel corporate", "Intel"), ("intel ", "Intel"), ("realtek", "Realtek"), ("murata", "Murata"), ("azurewave", "AzureWave"),
    ("lg electronics", "LG"), ("lg innotek", "LG Innotek"), ("sony", "Sony"), ("nintendo", "Nintendo"), ("microsoft", "Microsoft"),
    ("dell ", "Dell"), ("hewlett packard enterprise", "HPE"), ("hewlett packard", "HP"), ("hp inc", "HP"), ("asustek", "ASUS"),
    ("liteon", "Lite-On"), ("lite-on", "Lite-On"), ("ubiquiti", "Ubiquiti"), ("sonos", "Sonos"), ("signify", "Philips Hue"),
    ("philips lighting", "Philips Hue"), ("avm audiovisuelles", "AVM Fritz!"), ("avm gmbh", "AVM Fritz!"), ("netgear", "Netgear"),
    ("arcadyan", "Arcadyan"), ("technicolor", "Technicolor"), ("zte corporation", "ZTE"), ("cisco", "Cisco"), ("vantiva", "Vantiva"),
    ("oneplus", "OnePlus"), ("oppo", "OPPO"), ("vivo mobile", "vivo"), ("motorola", "Motorola"), ("lenovo", "Lenovo"),
    ("nokia", "Nokia"), ("ericsson", "Ericsson"), ("honor device", "Honor"), ("fairphone", "Fairphone"), ("garmin", "Garmin"),
    ("fitbit", "Fitbit"), ("roku", "Roku"), ("nvidia", "NVIDIA"), ("synology", "Synology"), ("qnap", "QNAP"),
    ("western digital", "Western Digital"), ("brother industries", "Brother"), ("canon", "Canon"), ("seiko epson", "Epson"),
    ("epson", "Epson"), ("lexmark", "Lexmark"), ("xerox", "Xerox"), ("kyocera", "Kyocera"), ("ricoh", "Ricoh"),
    ("netatmo", "Netatmo"), ("tuya", "Tuya"), ("shelly", "Shelly"), ("allterco", "Shelly"), ("ring llc", "Ring"),
    ("arlo", "Arlo"), ("ecobee", "ecobee"), ("nest labs", "Google Nest"), ("bose", "Bose"), ("harman", "Harman"),
    ("panasonic", "Panasonic"), ("sharp", "Sharp"), ("toshiba", "Toshiba"), ("hisense", "Hisense"), ("tcl ", "TCL"),
    ("vizio", "Vizio"), ("philips", "Philips"), ("withings", "Withings"), ("d-link", "D-Link"), ("zyxel", "Zyxel"),
    ("mikrotik", "MikroTik"), ("routerboard", "MikroTik"), ("juniper", "Juniper"), ("aruba", "Aruba"), ("ruckus", "Ruckus"),
    ("fortinet", "Fortinet"), ("vmware", "VMware"), ("parallels", "Parallels"), ("oracle", "Oracle"), ("super micro", "Supermicro"),
    ("gigabyte", "Gigabyte"), ("micro-star", "MSI"), ("asrock", "ASRock"), ("acer", "Acer"), ("compal", "Compal"),
    ("quanta", "Quanta"), ("pegatron", "Pegatron"), ("wistron", "Wistron"), ("universal global", "USI"), ("chongqing fugui", "Fugui"),
    ("texas instruments", "Texas Instruments"), ("silicon laboratories", "Silicon Labs"), ("nordic semiconductor", "Nordic"),
    ("qualcomm", "Qualcomm"), ("broadcom", "Broadcom"), ("mediatek", "MediaTek"), ("marvell", "Marvell"), ("cypress", "Cypress"),
    ("bouygues", "Bouygues Telecom"), ("orange", "Orange"), ("societe francaise du radiotelephone", "SFR"), ("sfr", "SFR"),
    ("deutsche telekom", "Deutsche Telekom"), ("vodafone", "Vodafone"), ("free mobile", "Free"), ("iliad", "Free"),
    ("pt inova", "Altice Labs"), ("altice labs", "Altice Labs"), ("tesla", "Tesla"), ("valve", "Valve"), ("meta platforms", "Meta"), ("oculus", "Meta"), ("facebook", "Meta"),
    ("logitech", "Logitech"), ("ikea", "IKEA"), ("dyson", "Dyson"), ("irobot", "iRobot"), ("ecovacs", "Ecovacs"),
    ("roborock", "Roborock"), ("dreame", "Dreame"), ("eufy", "Anker"), ("anker", "Anker"), ("wyze", "Wyze"),
    ("hikvision", "Hikvision"), ("dahua", "Dahua"), ("axis communications", "Axis"), ("reolink", "Reolink"),
    ("ezviz", "EZVIZ"), ("foscam", "Foscam"), ("yealink", "Yealink"), ("polycom", "Polycom"), ("grandstream", "Grandstream"),
    ("gopro", "GoPro"), ("dji", "DJI"), ("blackberry", "BlackBerry"), ("htc", "HTC"), ("asus", "ASUS"),
    ("belkin", "Belkin"), ("linksys", "Linksys"), ("buffalo", "Buffalo"), ("tenda", "Tenda"), ("mercusys", "Mercusys"),
    ("devolo", "devolo"), ("tado", "tado°"), ("somfy", "Somfy"), ("legrand", "Legrand"), ("schneider", "Schneider Electric"),
    ("siemens", "Siemens"), ("bosch", "Bosch"), ("miele", "Miele"), ("electrolux", "Electrolux"), ("whirlpool", "Whirlpool"),
]

SUFFIX = re.compile(
    r"[\s,.]*\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|gmbh|ag|sa|s\.a|sas|s\.a\.s|sarl|srl|s\.r\.l|spa|s\.p\.a|bv|b\.v|nv|n\.v|ab|oy|as|a/s|kg|plc|pte|pty|pvt|private|kabushiki kaisha|k\.k|ltda|zrt|sp\. z o\.o|technology|technologies|tech|electronics|electronic|international|industries|industrial|holdings|group|manufacturing|communication|communications|systems|solutions|products)\b\.?",
    re.I,
)


def short(name: str) -> str:
    low = name.lower()
    for key, brand in BRANDS:
        if key in low:
            return brand
    m = re.search(r"[（(]([A-Za-z][^）)]*)[）)]", name)
    if m and not name.isascii():
        name = m.group(1)
    n = re.sub(r"[（(].*?[）)]", "", name)
    n = n.replace("\t", " ").strip()
    prev = None
    while prev != n:
        prev = n
        n = SUFFIX.sub("", n).strip(" ,.-&")
    if not n:
        n = name.strip()
    if n.isupper() and len(n) > 4:
        n = " ".join(w.capitalize() if len(w) > 3 else w for w in n.split())
    words = n.split()[:3]
    while len(words) > 1 and words[-1].lower() in {"e", "y", "and", "und", "et", "de", "of", "the", "&", "-", "for", "da", "do", "di"}:
        words.pop()
    n = " ".join(words)
    return n[:28].strip(" ,.-&/")


rows = {}
with open(src, newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        if r["Registry"] != "MA-L":
            continue
        rows[r["Assignment"].upper()] = short(r["Organization Name"])

with open(dst, "w", encoding="utf-8", newline="\n") as f:
    f.write("# Fabricants des cartes réseau (préfixe MAC 24 bits), d'après le registre public de l'IEEE.\n")
    for k in sorted(rows):
        f.write(f"{k}\t{rows[k]}\n")
print(len(rows))
