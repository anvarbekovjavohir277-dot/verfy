"""Verfy: security, policy and verifiable evidence for coding agents and MCP tools.

Guard every tool call with deterministic rules, scan and lock MCP tool
definitions, and sign a tamper-evident receipt for everything that happened.
"""

from .canonical import canonical, digest
from .policy import DEFAULT_POLICY, load_policy, policy_digest
from .precheck import check, classify
from .scanner import scan, tool_pin

__version__ = "0.7.0"

__all__ = ["canonical", "digest", "DEFAULT_POLICY", "load_policy", "policy_digest", "check", "classify", "scan", "tool_pin", "__version__"]
