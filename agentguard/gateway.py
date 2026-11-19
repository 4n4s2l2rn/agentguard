"""Tool gateway: the Policy Enforcement Point between agents and tools.

Agents never call tools directly. Every call goes through ``ToolGateway.call``,
which (each step can be toggled for experiments):

1. exchanges the agent's token for a per-tool, least-privilege token (OAuth scopes)
2. builds an ABAC request with the data label, control label and sink level
3. asks the policy engine; CONFIRM decisions go to a human approver
4. scans retrieved documents for injection patterns (optional detector)
5. redacts PII from anything leaving the organisation (Presidio)
6. writes a hash-chained audit record
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from . import pii
from .audit import AuditLog
from .detector import injection_score
from .environment import TOOL_SPECS, Environment
from .identity import AuthError, AuthServer
from .labels import Conf, Label, Labeled
from .policy import ALLOW, CONFIRM, DENY, AccessRequest, Decision, PolicyConfig, PolicyEngine

Approver = Callable[[str, dict, Decision], bool]


@dataclass
class GuardConfig:
    name: str = "full"
    scopes: bool = True
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    pii: bool = True
    detector: bool = False
    detector_threshold: float = 0.4


@dataclass
class GatewayResult:
    ok: bool
    value: Labeled | None
    decision: Decision
    redacted: list[str] = field(default_factory=list)


class ToolGateway:
    def __init__(self, env: Environment, auth: AuthServer, cfg: GuardConfig,
                 approver: Approver | None = None, audit: AuditLog | None = None):
        self.env = env
        self.auth = auth
        self.cfg = cfg
        self.policy = PolicyEngine(cfg.policy)
        self.approver = approver or (lambda tool, args, decision: False)
        self.audit = audit or AuditLog()
        self.confirmations = 0
        self.latencies_ms: list[float] = []

    def call(self, token: str, tool: str, args: dict, data_label: Label, control_label: Label,
             fallback_subject: dict) -> GatewayResult:
        t0 = time.perf_counter()
        try:
            return self._call(token, tool, args, data_label, control_label, fallback_subject)
        finally:
            self.latencies_ms.append((time.perf_counter() - t0) * 1000)

    def _call(self, token, tool, args, data_label, control_label, fallback_subject) -> GatewayResult:
        scope, kind = TOOL_SPECS[tool]

        # 1. identity and least privilege
        if self.cfg.scopes:
            try:
                tool_token = self.auth.token_exchange(token, audience=f"tool:{tool}", scope=scope)
                claims = self.auth.verify(tool_token, audience=f"tool:{tool}", required_scope=scope)
            except AuthError as exc:
                return self._deny(tool, args, Decision(DENY, "R0-scope", str(exc)), fallback_subject["id"])
            subject = {"id": claims["act"]["sub"], "clearance": Conf(claims["clr"]),
                       "scopes": set(claims["scope"].split())}
        else:
            subject = fallback_subject

        # 2. build ABAC request
        req = AccessRequest(subject=subject, action=tool, kind=kind,
                            data_label=data_label, control_label=control_label)
        if tool in ("read_document", "delete_document"):
            doc = self.env.docs.get(args["doc_id"])
            req.resource = {"conf": doc.conf if doc else Conf.PUBLIC}
        elif tool == "send_email":
            req.sink_level = self.env.email_sink_level(args["to"])
        elif tool == "http_get":
            req.sink_level = self.env.url_sink_level(args["url"])

        # 3. decide
        decision = self.policy.evaluate(req)
        if decision.effect == CONFIRM:
            self.confirmations += 1
            approved = self.approver(tool, args, decision)
            decision = Decision(ALLOW if approved else DENY, decision.rule,
                                decision.reason + (" | human approved" if approved else " | human rejected"))
        if decision.effect == DENY:
            return self._deny(tool, args, decision, subject["id"])

        # 4/5. execute with content controls
        redacted: list[str] = []
        if tool == "read_document":
            value = self.env.read_document(args["doc_id"])
            if self.cfg.detector and injection_score(value.value) >= self.cfg.detector_threshold:
                return self._deny(tool, args, Decision(DENY, "detector", "prompt-injection pattern in content"),
                                  subject["id"])
        elif tool == "send_email":
            body = args["body"]
            if self.cfg.pii and self.env.is_external(args["to"]):
                body, redacted = pii.redact(body)
            value = self.env.send_email(args["to"], args.get("subject", ""), body)
        elif tool == "http_get":
            value = self.env.http_get(args["url"])
        else:
            value = self.env.delete_document(args["doc_id"])

        self.audit.append({"agent": subject["id"], "tool": tool, "args": _short(args),
                           "decision": decision.effect, "rule": decision.rule,
                           "data": data_label.short(), "control": control_label.short(),
                           "pii_redacted": redacted})
        return GatewayResult(True, value, decision, redacted)

    def _deny(self, tool, args, decision, agent_id) -> GatewayResult:
        self.audit.append({"agent": agent_id, "tool": tool, "args": _short(args),
                           "decision": DENY, "rule": decision.rule, "reason": decision.reason})
        return GatewayResult(False, None, decision)


def _short(args: dict) -> dict:
    return {k: (v[:60] + "...") if isinstance(v, str) and len(v) > 60 else v for k, v in args.items()}
