"""Reconnaissance tool registry (10 tools, in menu order)."""

from bugx.modules.recon.adapters.amass import AmassAdapter
from bugx.modules.recon.adapters.cloudlist import CloudlistAdapter
from bugx.modules.recon.adapters.dnsx import DnsxAdapter
from bugx.modules.recon.adapters.httpx import HttpxAdapter
from bugx.modules.recon.adapters.katana import KatanaAdapter
from bugx.modules.recon.adapters.naabu import NaabuAdapter
from bugx.modules.recon.adapters.nmap import NmapAdapter
from bugx.modules.recon.adapters.subfinder import SubfinderAdapter
from bugx.modules.recon.adapters.tlsx import TlsxAdapter
from bugx.modules.recon.adapters.whatweb import WhatWebAdapter

RECON_ADAPTERS = [
    SubfinderAdapter(),
    AmassAdapter(),
    DnsxAdapter(),
    HttpxAdapter(),
    NmapAdapter(),
    NaabuAdapter(),
    KatanaAdapter(),
    WhatWebAdapter(),
    TlsxAdapter(),
    CloudlistAdapter(),
]
