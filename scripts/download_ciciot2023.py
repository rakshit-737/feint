"""Download a CIC-IoT2023 subsample (flow records re-exported from the official PCAPs).

Source of truth: Neto et al., "CICIoT2023", Sensors 23(13):5941, 2023
(https://www.unb.ca/cic/datasets/iotdataset-2023.html). The official CSVs are behind a form and
use a closed, window-based feature extractor; the full PCAPs are ~587 GB. We therefore use the
Hugging Face mirror ``Lystea/CICIOT2023-PARQUET``: every official PCAP re-exported as
bidirectional flows with the open ipfixprobe 5.7.0 exporter (labels = source capture).

Subsample (16 GB RAM, and a slow shared link): one Parquet file per attack class (the smallest
one) plus all four benign captures, *excluding* the five flood classes whose smallest file alone
is 34-148 MB (DDoS-PSHACK/RSTFIN/SYN/TCP floods, Mirai-greip) -> 32 files, ~120 MB of the 19.4 GB
mirror, 28 attack classes. Results on this ipfixprobe re-export are NOT comparable with
the official CSV features of Neto et al. The loader further subsamples per class.

Usage:  python scripts/download_ciciot2023.py [--dest .../ciciot2023]
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from _fetch import fetch

BASE = "https://huggingface.co/datasets/Lystea/CICIOT2023-PARQUET/resolve/main/"
FILES = [
    ("Backdoor_Malware__Backdoor_Malware.parquet",
     "3534c5ab934a7bbf15a3c602406917435be2bbb5b878329598c648ae52a05fc6"),
    ("Benign_Final__BenignTraffic.parquet",
     "c773d9720a95eb64d778fc6fc6585e20e104fa33d4ec77ae1671e8ba326afa67"),
    ("Benign_Final__BenignTraffic1.parquet",
     "0cdd42a682ade6e4191654c973bc013075cc3212a1db9b50fedb7ee17e7718fe"),
    ("Benign_Final__BenignTraffic2.parquet",
     "2de346b765eb34e526f3110e2e068c7ce2a5266cb36d14e35e292fd93d857167"),
    ("Benign_Final__BenignTraffic3.parquet",
     "832dbbd0c9c9c7b4eab6d66459997cbedb758d2c367871d076df32bd10826534"),
    ("BrowserHijacking__BrowserHijacking.parquet",
     "332b5458dad31578c70dce5400d945662186dd421d819635ae75f9a592a670ea"),
    ("CommandInjection__CommandInjection.parquet",
     "dc6f9e38e9ad7952d84835ac61b7560edb0b05b1ed0a782b06ac7f7046e9b3f0"),
    ("DDoS-ACK_Fragmentation__DDoS-ACK_Fragmentation12.parquet",
     "7fcbb6caa8e3902019a853ea64b6b147cf033d3cc563140715a31fd56f399948"),
    ("DDoS-HTTP_Flood__DDoS-HTTP_Flood-.parquet",
     "22346d230fad22f2b07368509a0c775b54573abb890c3e4fc18cc1ffa820c192"),
    ("DDoS-ICMP_Flood__DDoS-ICMP_Flood7.parquet",
     "7cdf7356ecc9d8fc0d36350be393605fa0daafc84e0acbc9f7385288343080cf"),
    ("DDoS-ICMP_Fragmentation__DDoS-ICMP_Fragmentation15.parquet",
     "e85f30f6176ff823710b9111f568f425ca940b38ce6e6611834b140154691720"),
    ("DDoS-SlowLoris__DDoS-SlowLoris.parquet",
     "e96b7e91be35bf56509c0d79e0fa553a9a13f855b5e6df701a40b1da2adb71aa"),
    ("DDoS-SynonymousIP_Flood__DDoS-SynonymousIP_Flood13.parquet",
     "ffbd60398a7100a902dbc5c49176e9812718e82604235d55a421e9582331e670"),
    ("DDoS-UDP_Flood__DDoS-UDP_Flood20.parquet",
     "261902f93a4cb1aeffa63449c7d4a696a94fac47045bd3ba173eaddadb02ec5e"),
    ("DDoS-UDP_Fragmentation__DDoS-UDP_Fragmentation9.parquet",
     "4e6e7726f36cd4acd45a13dd512b3b2bea4af71224445f1823846adf6f65f4a8"),
    ("DNS_Spoofing__DNS_Spoofing.parquet",
     "43c230d10851e0cca311f6b3edb4c6d35b49e9a61908e69d2e0b91a0fdbc3685"),
    ("DictionaryBruteForce__DictionaryBruteForce.parquet",
     "b1d2da487c66145b4c375172ecf9c82ee357f3b74ea82491eb996d98b19077d5"),
    ("DoS-HTTP_Flood__DoS-HTTP_Flood1.parquet",
     "6fdf337f658d56388afe0afd22e7e21b623c839628f8a8a536bd2f0e17637f77"),
    ("DoS-SYN_Flood__DoS-SYN_Flood1.parquet",
     "bcb5a96f72d4458a5aa42d8edf913f063600a87aefee2f55257e9b6b7a817cb4"),
    ("DoS-TCP_Flood__DoS-TCP_Flood10.parquet",
     "898cd1308211d8942880c5703968f3d21992c01d065d85a21f3c6991ff73dc94"),
    ("DoS-UDP_Flood__DoS-UDP_Flood16.parquet",
     "439aa432b7ce1811bc0e289e995f0d123343b4f38cf6818481341b51bc2eef54"),
    ("MITM-ArpSpoofing__MITM-ArpSpoofing1.parquet",
     "8063bf7a791ab63070819f8746e6b68dc55b5b8ad58a6f9a49216a9f9537aa53"),
    ("Mirai-greeth_flood__Mirai-greeth_flood24.parquet",
     "1778f333cf399b2ca6caa6e6c6a157e3a6ffd239dcaa9b61b2a2e334b9cc71fe"),
    ("Mirai-udpplain__Mirai-udpplain11.parquet",
     "48c748e268d24c8842cf2a93180afc3f18d3786535833816c767ecfc30a3f357"),
    ("Recon-HostDiscovery__Recon-HostDiscovery.parquet",
     "cd07c6f2db1e0455eb0b5e222fa9bef74d789e2b0f710c1d740ccbf68bceb877"),
    ("Recon-OSScan__Recon-OSScan.parquet",
     "e26818bd028b62534571185cd39efb88beee8d6d19c61497a948ec66674d48ea"),
    ("Recon-PingSweep__Recon-PingSweep.parquet",
     "add2b50eb393b226fdfd46f5d4129c71a4c7612de42962b2eabe8697da2a94e8"),
    ("Recon-PortScan__Recon-PortScan.parquet",
     "da203b9c85cf977796d384858698fd42d77f54249e85f6294dc71845ad437544"),
    ("SqlInjection__SqlInjection.parquet",
     "1910ff798e34f917dee264cb1438ad2d0d75294ffb26d05c73dc4e357a924d93"),
    ("Uploading_Attack__Uploading_Attack.parquet",
     "60ae23539f798ff0ce67ba5ae08bf2007cfb7f5f2a5bfe032eb402ebba3dd104"),
    ("VulnerabilityScan__VulnerabilityScan.parquet",
     "1a67a03f4bc27d1b6a419a4652345210a3769079a6d9ab052f5010a7c1fea368"),
    ("XSS__XSS.parquet",
     "80dacb710e501f304d1d429489c39b7e627cb01fb35c79110167d2164c49461a"),
]
DEFAULT = Path(os.environ.get("FEINT_DATA", Path(__file__).resolve().parents[1] / "data")) / "ciciot2023"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", type=Path, default=DEFAULT)
    a = ap.parse_args()
    for name, sha in FILES:
        fetch(BASE + name, a.dest / name, sha)


if __name__ == "__main__":
    main()
