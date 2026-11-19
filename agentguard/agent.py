"""Agents and a deterministic stand-in for the LLM.

``SimulatedLLM`` is intentionally *vulnerable*: like a real instruction-tuned model,
it follows imperative sentences wherever they appear, including inside documents
it reads. Making it deterministic lets every experiment be reproduced exactly;
the security controls being tested sit outside the model, so they do not depend
on which model is plugged in.

Two agent architectures are compared:

* ``naive``: one LLM sees the user task *and* every document, then decides tool
  calls. Everything it outputs is tainted by everything it has read.
* ``dual``: dual-LLM / plan-then-execute pattern. A privileged planner sees only
  the trusted user task and fixes the plan before any data is read. Documents
  are handled by a quarantined summarizer with no tool access, and are passed
  around as references, so labels stay precise.
"""
from __future__ import annotations

import re
import urllib.parse
from collections import deque
from dataclasses import dataclass, field

from .gateway import ToolGateway
from .identity import AuthServer
from .labels import Conf, Integ, Label, Labeled

USER_TASK_LABEL = Label(Conf.PUBLIC, Integ.TRUSTED, frozenset({"user"}))

_DOC = r"document\s+([a-z0-9][\w-]*)"
_EMAIL = r"([\w.+-]+@[\w-]+(?:\.[\w-]+)+)"


def parse_intents(text: str) -> list[tuple]:
    """Very small 'instruction follower': turns sentences into tool intents."""
    intents: list[tuple] = []
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", text):
        s = sentence.strip()
        low = s.lower()
        if not s:
            continue
        docs = re.findall(_DOC, low)
        emails = re.findall(_EMAIL, low)
        urls = re.findall(r"https?://\S+", s)
        if docs and re.search(r"\b(delete|remove|erase|wipe)\b", low):
            intents.append(("delete", docs[0]))
        elif urls and re.search(r"\b(load|fetch|open|render|visit|call)\b", low):
            intents.append(("fetch", urls[0].rstrip(".,")))
        elif emails and re.search(r"\b(send|email|forward|dispatch|mail|share)\b", low):
            if docs and re.search(r"\b(summari[sz]e|read)\b", low):
                intents.append(("read", docs[0]))
            full = bool(re.search(r"\b(full|verbatim|entire|complete|contents|copy)\b", low))
            intents.append(("email", emails[0], docs[-1] if docs else None, "full" if full else "summary"))
        elif docs and re.search(r"\b(summari[sz]e|read|review)\b", low):
            intents.append(("read", docs[0]))
    return intents


def summarize(text: str) -> str:
    """Quarantined summarizer: returns the first sentence. It has no tools."""
    return re.split(r"(?<=[.!?])\s+", text.strip())[0]


@dataclass
class StepLog:
    intent: tuple
    ok: bool
    rule: str
    reason: str


@dataclass
class Trace:
    steps: list[StepLog] = field(default_factory=list)


class Agent:
    def __init__(self, name: str, secret: str, clearance: Conf, gateway: ToolGateway,
                 auth: AuthServer, mode: str = "naive", max_steps: int = 10):
        self.name, self.secret, self.clearance = name, secret, clearance
        self.gw, self.auth, self.mode, self.max_steps = gateway, auth, mode, max_steps

    # -- helpers ------------------------------------------------------------------
    def _token(self, user: str) -> str:
        return self.auth.client_credentials(self.name, self.secret, on_behalf_of=user)

    def _subject(self) -> dict:
        return {"id": self.name, "clearance": self.clearance, "scopes": set()}

    def _call(self, trace: Trace, intent, token, tool, args, data: Label, control: Label):
        res = self.gw.call(token, tool, args, data, control, self._subject())
        trace.steps.append(StepLog(intent, res.ok, res.decision.rule, res.decision.reason))
        return res

    def read(self, doc_id: str, token: str, trace: Trace, control: Label) -> Labeled | None:
        res = self._call(trace, ("read", doc_id), token, "read_document", {"doc_id": doc_id}, control, control)
        return res.value if res.ok else None

    # -- main loop ----------------------------------------------------------------
    def run(self, task: str, user: str = "alice") -> Trace:
        return self._run_dual(task, user) if self.mode == "dual" else self._run_naive(task, user)

    def _run_naive(self, task: str, user: str) -> Trace:
        trace, token = Trace(), self._token(user)
        ctx = USER_TASK_LABEL          # label of everything the model has seen so far
        memory: dict[str, str] = {}
        last_doc = None
        queue = deque(parse_intents(task))
        steps = 0
        while queue and steps < self.max_steps:
            steps += 1
            intent = queue.popleft()
            kind = intent[0]
            if kind == "read":
                val = self.read(intent[1], token, trace, ctx)
                if val is not None:
                    memory[intent[1]] = val.value
                    ctx = ctx.join(val.label)
                    last_doc = intent[1]
                    queue.extend(parse_intents(val.value))   # the vulnerability: data becomes instructions
            elif kind == "email":
                _, to, doc_id, how = intent
                doc_id = doc_id or last_doc
                if doc_id and doc_id not in memory:
                    val = self.read(doc_id, token, trace, ctx)
                    if val is None:
                        continue
                    memory[doc_id] = val.value
                    ctx = ctx.join(val.label)
                text = memory.get(doc_id, "")
                body = text if how == "full" else summarize(text)
                self._call(trace, intent, token, "send_email",
                           {"to": to, "subject": f"Re: {doc_id}", "body": body}, ctx, ctx)
            elif kind == "fetch":
                url = intent[1]
                for ref in re.findall(r"\{doc:([\w-]+)\}", url):
                    if ref not in memory:
                        val = self.read(ref, token, trace, ctx)
                        if val is None:
                            break
                        memory[ref] = val.value
                        ctx = ctx.join(val.label)
                    url = url.replace("{doc:%s}" % ref, urllib.parse.quote(memory[ref]))
                if "{doc:" in url:
                    continue
                self._call(trace, intent, token, "http_get", {"url": url}, ctx, ctx)
            elif kind == "delete":
                self._call(trace, intent, token, "delete_document", {"doc_id": intent[1]}, ctx, ctx)
        return trace

    def _run_dual(self, task: str, user: str) -> Trace:
        trace, token = Trace(), self._token(user)
        control = USER_TASK_LABEL                  # the plan only ever depends on the user's words
        plan = parse_intents(task)                 # fixed before any untrusted data is read
        variables: dict[str, Labeled] = {}
        last_doc = None
        for intent in plan[: self.max_steps]:
            kind = intent[0]
            if kind == "read":
                val = self.read(intent[1], token, trace, control)
                if val is not None:
                    variables[intent[1]] = val     # stored by reference; never parsed for instructions
                    last_doc = intent[1]
            elif kind == "email":
                _, to, doc_id, how = intent
                doc_id = doc_id or last_doc
                if doc_id and doc_id not in variables:
                    val = self.read(doc_id, token, trace, control)
                    if val is None:
                        continue
                    variables[doc_id] = val
                var = variables.get(doc_id, Labeled(""))
                body = var.value if how == "full" else summarize(var.value)
                self._call(trace, intent, token, "send_email",
                           {"to": to, "subject": f"Re: {doc_id}", "body": body}, var.label, control)
            elif kind == "fetch":
                self._call(trace, intent, token, "http_get", {"url": intent[1]}, control, control)
            elif kind == "delete":
                self._call(trace, intent, token, "delete_document", {"doc_id": intent[1]}, control, control)
        return trace
