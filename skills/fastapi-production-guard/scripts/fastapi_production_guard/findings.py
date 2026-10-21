"""The one shape every rule reports in."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Confidence(StrEnum):
    """How sure the rule is that the code is wrong, not merely unusual.

    HIGH means every fact the finding rests on was read from your code — for
    FPG001, that the model really has an owner column. MEDIUM means one fact
    had to be assumed because it could not be resolved statically (a model
    reached through `self.model`, a repository method defined in a library).
    Only HIGH fails the scan by default; MEDIUM is printed for a person (or
    an agent) to confirm, and `--fail-on medium` makes it fail too.
    """

    HIGH = "high"
    MEDIUM = "medium"

    @property
    def rank(self) -> int:
        return {Confidence.MEDIUM: 1, Confidence.HIGH: 2}[self]


RULES: dict[str, str] = {
    "FPG001": "unscoped-resource-lookup",
    "FPG002": "webhook-without-dedupe",
    "FPG003": "unserialised-balance-update",
}

RULE_TITLES: dict[str, str] = {
    "FPG001": "User-owned resource looked up by a client-supplied id without the current user",
    "FPG002": "Webhook side effects run without deduplicating on the event id",
    "FPG003": "Balance read and written without serialising concurrent requests",
}


@dataclass(frozen=True)
class Location:
    path: str  # posix, relative to the scanned root
    line: int
    column: int = 0

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.column + 1}"


@dataclass(frozen=True)
class Finding:
    rule: str
    location: Location
    message: str
    confidence: Confidence
    # Where the finding is anchored for a human: the route or function.
    subject: str
    fix: str
    # The chain of facts the rule relied on, in the order it found them. An
    # agent fixing the finding needs these more than the message: they say
    # which line to change.
    evidence: tuple[str, ...] = field(default_factory=tuple)

    @property
    def rule_name(self) -> str:
        return RULES[self.rule]

    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.location.path, self.location.line, self.location.column, self.rule)


@dataclass(frozen=True)
class Suppressed:
    finding: Finding
    reason: str
