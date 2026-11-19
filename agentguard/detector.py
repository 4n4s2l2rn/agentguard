"""Heuristic prompt-injection detector.

Deliberately simple: it represents the "filter the input" family of defenses so the
evaluation can show both its value and its limits (paraphrases slip through, and
legitimate security-training documents get blocked).
"""
from __future__ import annotations

import re

PATTERNS: list[tuple[str, float]] = [
    (r"ignore (all |any )?(the )?(previous|prior|above) instructions", 0.6),
    (r"\b(system prompt|developer mode|you are now)\b", 0.4),
    (r"\b(send|email|forward)\b[^.]*\bto\s+[\w.+-]+@", 0.4),
    (r"https?://\S*\{[^}]+\}", 0.5),
    (r"\b(delete|erase|wipe)\b[^.]*\bdocument\b", 0.3),
]


def injection_score(text: str) -> float:
    lowered = text.lower()
    return min(1.0, sum(w for p, w in PATTERNS if re.search(p, lowered)))
