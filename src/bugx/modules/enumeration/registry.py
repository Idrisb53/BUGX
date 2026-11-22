"""Enumeration tool registry (10 tools, in menu order)."""

from bugx.modules.enumeration.adapters.arjun import ArjunAdapter
from bugx.modules.enumeration.adapters.dirsearch import DirsearchAdapter
from bugx.modules.enumeration.adapters.feroxbuster import FeroxbusterAdapter
from bugx.modules.enumeration.adapters.ffuf import FfufAdapter
from bugx.modules.enumeration.adapters.gowitness import GoWitnessAdapter
from bugx.modules.enumeration.adapters.hakrawler import HakrawlerAdapter
from bugx.modules.enumeration.adapters.kiterunner import KiterunnerAdapter
from bugx.modules.enumeration.adapters.linkfinder import LinkFinderAdapter
from bugx.modules.enumeration.adapters.paramspider import ParamSpiderAdapter
from bugx.modules.enumeration.adapters.secretfinder import SecretFinderAdapter

ENUMERATION_ADAPTERS = [
    FfufAdapter(),
    FeroxbusterAdapter(),
    DirsearchAdapter(),
    ArjunAdapter(),
    ParamSpiderAdapter(),
    KiterunnerAdapter(),
    LinkFinderAdapter(),
    SecretFinderAdapter(),
    HakrawlerAdapter(),
    GoWitnessAdapter(),
]
