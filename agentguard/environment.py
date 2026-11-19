"""Simulated company environment: documents, mail, web, and a principal directory.

Everything is in memory so experiments are deterministic and repeatable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .labels import Conf, Integ, Label, Labeled


@dataclass
class Document:
    doc_id: str
    text: str
    conf: Conf
    integ: Integ  # TRUSTED = authored by a verified internal owner; UNTRUSTED = external/shared content

    def label(self) -> Label:
        return Label(self.conf, self.integ, frozenset({f"doc:{self.doc_id}"}))


@dataclass
class Principal:
    """A mailbox owner known to the directory, with a data clearance."""

    address: str
    clearance: Conf


@dataclass
class Environment:
    docs: dict[str, Document] = field(default_factory=dict)
    directory: dict[str, Principal] = field(default_factory=dict)
    internal_domains: tuple[str, ...] = ("corp.example",)
    partner_domains: tuple[str, ...] = ("partner.example",)
    url_allowlist: tuple[str, ...] = ("docs.corp.example", "status.corp.example")
    outbox: list[dict] = field(default_factory=list)
    http_log: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)

    # -- sink classification used by the policy engine ---------------------------
    def email_sink_level(self, address: str) -> Conf:
        """Highest confidentiality an email recipient may receive."""
        principal = self.directory.get(address.lower())
        if principal is not None:
            return principal.clearance
        domain = address.rsplit("@", 1)[-1].lower()
        if domain in self.partner_domains:
            return Conf.INTERNAL
        return Conf.PUBLIC  # unknown internal users and all external addresses

    def is_external(self, address: str) -> bool:
        return address.rsplit("@", 1)[-1].lower() not in self.internal_domains

    def url_sink_level(self, url: str) -> Conf:
        host = re.sub(r"^https?://", "", url).split("/", 1)[0].lower()
        return Conf.INTERNAL if host in self.url_allowlist else Conf.PUBLIC

    # -- tool implementations (no security here: the gateway enforces it) --------
    def read_document(self, doc_id: str) -> Labeled:
        doc = self.docs.get(doc_id)
        if doc is None:
            raise KeyError(f"unknown document {doc_id}")
        return Labeled(doc.text, doc.label())

    def send_email(self, to: str, subject: str, body: str) -> Labeled:
        self.outbox.append({"to": to.lower(), "subject": subject, "body": body})
        return Labeled(f"sent to {to}")

    def http_get(self, url: str) -> Labeled:
        self.http_log.append(url)
        return Labeled("200 OK", Label(Conf.PUBLIC, Integ.UNTRUSTED, frozenset({"web"})))

    def delete_document(self, doc_id: str) -> Labeled:
        self.docs.pop(doc_id, None)
        self.deleted.append(doc_id)
        return Labeled(f"deleted {doc_id}")


# tool name -> (required OAuth scope, kind)
TOOL_SPECS: dict[str, tuple[str, str]] = {
    "read_document": ("docs.read", "read"),
    "send_email": ("mail.send", "egress"),
    "http_get": ("web.fetch", "egress"),
    "delete_document": ("docs.delete", "destructive"),
}
