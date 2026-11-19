"""Security labels for information-flow control (IFC).

Every piece of data an agent touches carries a label with two axes:

* confidentiality: who is allowed to *read* it (PUBLIC < INTERNAL < CONFIDENTIAL)
* integrity: who is allowed to *steer* the agent with it (TRUSTED > UNTRUSTED)

Labels only ever get stricter when data is combined (``join``): a summary of a
confidential document is still confidential, and anything an LLM produced after
reading untrusted text is untrusted. This is what stops "indirect" leaks such as
summaries, paraphrases or yes/no answers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Iterable


class Conf(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2


class Integ(IntEnum):
    UNTRUSTED = 0
    TRUSTED = 1


@dataclass(frozen=True)
class Label:
    conf: Conf = Conf.PUBLIC
    integ: Integ = Integ.TRUSTED
    sources: frozenset[str] = field(default_factory=frozenset)

    def join(self, other: "Label") -> "Label":
        """Least upper bound: max confidentiality, min integrity, union of sources."""
        return Label(
            conf=max(self.conf, other.conf),
            integ=min(self.integ, other.integ),
            sources=self.sources | other.sources,
        )

    @staticmethod
    def join_all(labels: Iterable["Label"]) -> "Label":
        out = Label()
        for lab in labels:
            out = out.join(lab)
        return out

    def flows_to(self, sink_level: Conf) -> bool:
        return self.conf <= sink_level

    def short(self) -> str:
        return f"{self.conf.name}/{self.integ.name}"


TRUSTED_PUBLIC = Label()


@dataclass(frozen=True)
class Labeled:
    """A value together with its label. Tools return Labeled values."""

    value: Any
    label: Label = TRUSTED_PUBLIC
