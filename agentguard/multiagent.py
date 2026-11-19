"""Trust boundary between two collaborating agents.

* ``analyst``: clearance CONFIDENTIAL, can read internal documents.
* ``public-assistant``: clearance PUBLIC, talks to the outside world.

All inter-agent traffic goes through ``AgentBus``. Messages and shared-store
entries keep the label of the data they were derived from, so the boundary
holds against indirect channels: summaries, yes/no answers, and writes to a
shared scratchpad. Declassification is an explicit, audited, human step.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .agent import USER_TASK_LABEL, summarize
from .audit import AuditLog
from .gateway import ToolGateway
from .identity import GATEWAY_AUDIENCE, AuthError, AuthServer
from .labels import Conf, Label, Labeled


@dataclass
class AgentBus:
    auth: AuthServer
    enforce_ifc: bool
    authenticate: bool
    clearances: dict[str, Conf]
    audit: AuditLog = field(default_factory=AuditLog)
    inbox: dict[str, list[Labeled]] = field(default_factory=dict)
    store: dict[str, Labeled] = field(default_factory=dict)

    def _sender(self, token: str, claimed: str) -> str | None:
        if not self.authenticate:
            return claimed
        try:
            return self.auth.verify(token, GATEWAY_AUDIENCE)["sub"]
        except AuthError:
            return None

    def send(self, token: str, sender: str, receiver: str, msg: Labeled) -> bool:
        who = self._sender(token, sender)
        if who is None:
            self.audit.append({"bus": "send", "from": sender, "to": receiver, "decision": "DENY", "rule": "authn"})
            return False
        if self.enforce_ifc and msg.label.conf > self.clearances[receiver]:
            self.audit.append({"bus": "send", "from": who, "to": receiver, "decision": "DENY",
                               "rule": "R2-ifc", "label": msg.label.short()})
            return False
        self.inbox.setdefault(receiver, []).append(msg)
        self.audit.append({"bus": "send", "from": who, "to": receiver, "decision": "ALLOW",
                           "label": msg.label.short()})
        return True

    def write(self, token: str, writer: str, key: str, value: Labeled) -> None:
        # a store entry can only get *more* restrictive when overwritten
        old = self.store.get(key)
        label = value.label if old is None else value.label.join(old.label)
        self.store[key] = Labeled(value.value, label)
        self.audit.append({"bus": "write", "by": self._sender(token, writer), "key": key, "label": label.short()})

    def read(self, token: str, reader: str, key: str) -> Labeled | None:
        who = self._sender(token, reader)
        entry = self.store.get(key)
        if who is None or entry is None:
            return None
        if self.enforce_ifc and entry.label.conf > self.clearances[reader]:
            self.audit.append({"bus": "read", "by": who, "key": key, "decision": "DENY", "rule": "R2-ifc"})
            return None
        return entry

    def declassify(self, msg: Labeled, to: Conf, approved_by: str, justification: str) -> Labeled:
        self.audit.append({"bus": "declassify", "from": msg.label.short(), "to": to.name,
                           "approved_by": approved_by, "justification": justification})
        return Labeled(msg.value, Label(to, msg.label.integ, msg.label.sources | {f"declassified:{approved_by}"}))


class AnalystAgent:
    """Answers questions from other agents using documents it is cleared to read."""

    def __init__(self, name: str, secret: str, gateway: ToolGateway, auth: AuthServer):
        self.name, self.secret, self.gw, self.auth = name, secret, gateway, auth

    def token(self) -> str:
        return self.auth.client_credentials(self.name, self.secret)

    def _read(self, doc_id: str, token: str) -> Labeled | None:
        res = self.gw.call(token, "read_document", {"doc_id": doc_id}, USER_TASK_LABEL, USER_TASK_LABEL,
                           {"id": self.name, "clearance": Conf.CONFIDENTIAL, "scopes": set()})
        return res.value if res.ok else None

    def answer(self, question: str, requester: str, bus: AgentBus) -> bool:
        token = self.token()
        low = question.lower()
        m = re.search(r"document\s+([\w-]+)", low)
        if not m:
            return False
        doc = self._read(m.group(1), token)
        if doc is None:
            return False
        if (q := re.search(r"mention\s+['\"]?([\w-]+)", low)):
            reply = "yes" if q.group(1) in doc.value.lower() else "no"   # 1 bit, still derived from the doc
        elif re.search(r"\b(full|contents|verbatim)\b", low):
            reply = doc.value
        else:
            reply = summarize(doc.value)
        return bus.send(token, self.name, requester, Labeled(reply, doc.label))

    def save_summary(self, doc_id: str, key: str, bus: AgentBus) -> None:
        token = self.token()
        doc = self._read(doc_id, token)
        if doc is not None:
            bus.write(token, self.name, key, Labeled(summarize(doc.value), doc.label))
