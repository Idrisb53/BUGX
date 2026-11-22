"""Vulnerability-analysis tool registry (10 tools, in menu order)."""

from bugx.modules.analysis.adapters.dalfox import DalfoxAdapter
from bugx.modules.analysis.adapters.nikto import NiktoAdapter
from bugx.modules.analysis.adapters.nuclei import NucleiAdapter
from bugx.modules.analysis.adapters.retire import RetireAdapter
from bugx.modules.analysis.adapters.semgrep import SemgrepAdapter
from bugx.modules.analysis.adapters.sqlmap import SqlmapAdapter
from bugx.modules.analysis.adapters.testssl import TestsslAdapter
from bugx.modules.analysis.adapters.trivy import TrivyAdapter
from bugx.modules.analysis.adapters.wapiti import WapitiAdapter
from bugx.modules.analysis.adapters.zap import ZapAdapter

ANALYSIS_ADAPTERS = [
    NucleiAdapter(),
    ZapAdapter(),
    NiktoAdapter(),
    TestsslAdapter(),
    DalfoxAdapter(),
    SqlmapAdapter(),
    WapitiAdapter(),
    RetireAdapter(),
    TrivyAdapter(),
    SemgrepAdapter(),
]
