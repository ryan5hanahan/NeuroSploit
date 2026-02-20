"""
sploit.ai - OSINT API Clients

API-based open-source intelligence gathering. Provides enrichment data
that CLI recon tools cannot access (e.g., Shodan host info, Censys certs,
VirusTotal reputation, BuiltWith tech profiling).
"""

from backend.core.osint.aggregator import OSINTAggregator
from backend.core.osint.securitytrails import SecurityTrailsClient
from backend.core.osint.fofa import FOFAClient
from backend.core.osint.zoomeye import ZoomEyeClient
from backend.core.osint.github_dork import GitHubDorkClient
from backend.core.osint.dehashed import DehashedClient
from backend.core.osint.hibp import HIBPClient
from backend.core.osint.grayhat_warfare import GrayhatWarfareClient
from backend.core.osint.publicwww import PublicWWWClient

__all__ = [
    "OSINTAggregator",
    "SecurityTrailsClient",
    "FOFAClient",
    "ZoomEyeClient",
    "GitHubDorkClient",
    "DehashedClient",
    "HIBPClient",
    "GrayhatWarfareClient",
    "PublicWWWClient",
]
