"""Attribute-based access control (ABAC) policy decision point.

A request is (subject, action, resource, context) attributes. Rules are evaluated
in order with deny-overrides; the first DENY wins, otherwise the strictest of
CONFIRM / ALLOW is returned. Each rule can be switched off to measure what it
contributes (see ``evaluate.py``).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .labels import Conf, Integ, Label

ALLOW, CONFIRM, DENY = "ALLOW", "CONFIRM", "DENY"


@dataclass
class AccessRequest:
    subject: dict           # {"id", "clearance": Conf, "scopes": set}
    action: str             # tool name
    kind: str               # read | egress | destructive
    resource: dict = field(default_factory=dict)   # e.g. {"conf": Conf} for reads
    data_label: Label = field(default_factory=Label)     # label of the arguments
    control_label: Label = field(default_factory=Label)  # label of what decided to call the tool
    sink_level: Conf | None = None                 # max level the destination may receive


@dataclass
class Decision:
    effect: str
    rule: str
    reason: str


@dataclass
class PolicyConfig:
    clearance: bool = True        # R1: subject clearance >= resource classification
    ifc: bool = True              # R2: data label must flow to the sink
    integrity: bool = True        # R3: untrusted control flow -> human confirmation
    destructive_confirm: bool = True  # R4: destructive actions always confirmed


class PolicyEngine:
    def __init__(self, cfg: PolicyConfig):
        self.cfg = cfg

    def evaluate(self, req: AccessRequest) -> Decision:
        cfg = self.cfg
        # R1 - ABAC clearance on reads
        if cfg.clearance and req.kind == "read":
            res_conf = req.resource.get("conf", Conf.PUBLIC)
            if res_conf > req.subject["clearance"]:
                return Decision(DENY, "R1-clearance",
                                f"{req.subject['id']} clearance {req.subject['clearance'].name} < {res_conf.name}")
        # R2 - information-flow control on egress
        if cfg.ifc and req.kind == "egress" and req.sink_level is not None:
            if not req.data_label.flows_to(req.sink_level):
                return Decision(DENY, "R2-ifc",
                                f"data {req.data_label.conf.name} cannot flow to sink {req.sink_level.name}")
        # R3 - integrity: a side effect decided under untrusted influence needs a human
        if cfg.integrity and req.kind != "read" and req.control_label.integ == Integ.UNTRUSTED:
            return Decision(CONFIRM, "R3-integrity",
                            f"action influenced by untrusted sources {sorted(req.control_label.sources)}")
        # R4 - destructive actions
        if cfg.destructive_confirm and req.kind == "destructive":
            return Decision(CONFIRM, "R4-destructive", "destructive action requires confirmation")
        return Decision(ALLOW, "default", "no rule matched")
