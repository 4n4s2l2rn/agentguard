"""Minimal OAuth 2.0 / OIDC-style authorization server for agents.

Implements, in-process, the two grants an agent platform needs:

* ``client_credentials`` (RFC 6749 s4.4): each agent is a confidential client
  with its own identity, allowed scopes and data clearance.
* ``token exchange`` (RFC 8693): before calling a tool the agent swaps its
  broad token for a short-lived token whose audience is *that one tool* and
  whose scope is the minimum needed (least privilege, no token replay across
  tools). The ``act`` claim records the agent acting on behalf of the user.

Tokens are RS256 JWTs; the public key is published as a JWKS like a real
OIDC provider. Swapping this for Keycloak/Auth0 only changes this module.
"""
from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from .labels import Conf

GATEWAY_AUDIENCE = "agentguard-gateway"


class AuthError(Exception):
    pass


@dataclass
class Client:
    client_id: str
    secret_hash: bytes
    scopes: frozenset[str]
    clearance: Conf


class AuthServer:
    def __init__(self, issuer: str = "https://auth.agentguard.local", ttl: int = 300):
        self.issuer = issuer
        self.ttl = ttl
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = uuid.uuid4().hex[:12]
        self.clients: dict[str, Client] = {}

    # --- discovery -----------------------------------------------------------
    def discovery(self) -> dict:
        return {
            "issuer": self.issuer,
            "token_endpoint": f"{self.issuer}/token",
            "jwks_uri": f"{self.issuer}/.well-known/jwks.json",
            "grant_types_supported": [
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def jwks(self) -> dict:
        jwk = RSAAlgorithm.to_jwk(self._key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    # --- registration ----------------------------------------------------------
    def register_client(self, client_id: str, secret: str, scopes: set[str], clearance: Conf) -> None:
        self.clients[client_id] = Client(
            client_id, hashlib.sha256(secret.encode()).digest(), frozenset(scopes), clearance
        )

    # --- grants ---------------------------------------------------------------
    def client_credentials(self, client_id: str, secret: str, scope: str | None = None,
                           on_behalf_of: str | None = None) -> str:
        client = self.clients.get(client_id)
        if client is None or not hmac.compare_digest(
            client.secret_hash, hashlib.sha256(secret.encode()).digest()
        ):
            raise AuthError("invalid_client")
        requested = set(scope.split()) if scope else set(client.scopes)
        if not requested <= client.scopes:
            raise AuthError(f"invalid_scope: {sorted(requested - client.scopes)}")
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": client_id,
            "aud": GATEWAY_AUDIENCE,
            "scope": " ".join(sorted(requested)),
            "clr": int(client.clearance),
            "iat": now,
            "exp": now + self.ttl,
            "jti": uuid.uuid4().hex,
        }
        if on_behalf_of:
            claims["obo"] = on_behalf_of
        return self._sign(claims)

    def token_exchange(self, subject_token: str, audience: str, scope: str) -> str:
        parent = self.verify(subject_token, GATEWAY_AUDIENCE)
        requested = set(scope.split())
        granted = set(parent["scope"].split())
        if not requested <= granted:
            raise AuthError(f"insufficient_scope: {sorted(requested - granted)}")
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": parent.get("obo", parent["sub"]),
            "act": {"sub": parent["sub"]},
            "aud": audience,
            "scope": " ".join(sorted(requested)),
            "clr": parent["clr"],
            "iat": now,
            "exp": min(parent["exp"], now + 60),
            "jti": uuid.uuid4().hex,
        }
        return self._sign(claims)

    # --- verification -----------------------------------------------------------
    def verify(self, token: str, audience: str, required_scope: str | None = None) -> dict:
        try:
            claims = jwt.decode(
                token, self._key.public_key(), algorithms=["RS256"],
                audience=audience, issuer=self.issuer,
                options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid_token: {exc}") from exc
        if required_scope and required_scope not in claims["scope"].split():
            raise AuthError(f"insufficient_scope: {required_scope}")
        return claims

    def _sign(self, claims: dict) -> str:
        return jwt.encode(claims, self._key, algorithm="RS256", headers={"kid": self.kid})
