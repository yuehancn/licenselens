"""licenselens - find the licenses that will stop you shipping.

The public surface is intentionally small: ``judge`` for a document,
``judge_expression`` for an SPDX string, ``evaluate`` for a decision, and
``Prober`` for repositories.
"""

from .judge import (
    COMMERCIAL_CONDITIONAL,
    COMMERCIAL_FORBIDDEN,
    COMMERCIAL_OK,
    COMMERCIAL_UNKNOWN,
    COPYLEFT_FILE,
    COPYLEFT_NETWORK,
    COPYLEFT_NONE,
    COPYLEFT_PROJECT,
    PROFILE_BY_ID,
    PROFILES,
    Verdict,
    explain,
    judge,
    judge_expression,
)
from .policy import Decision, Finding, Policy, RiskKind, evaluate
from .probe import Prober, RepoRecord

__version__ = "0.1.1"

__all__ = [
    "COMMERCIAL_CONDITIONAL",
    "COMMERCIAL_FORBIDDEN",
    "COMMERCIAL_OK",
    "COMMERCIAL_UNKNOWN",
    "COPYLEFT_FILE",
    "COPYLEFT_NETWORK",
    "COPYLEFT_NONE",
    "COPYLEFT_PROJECT",
    "Decision",
    "Finding",
    "PROFILES",
    "PROFILE_BY_ID",
    "Policy",
    "Prober",
    "RepoRecord",
    "RiskKind",
    "Verdict",
    "__version__",
    "evaluate",
    "explain",
    "judge",
    "judge_expression",
]