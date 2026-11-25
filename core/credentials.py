"""Credential resolution. Sites store a *reference*; the Application Password is resolved per call.

The only reference is ``{"env": "WPM_<ID>_APP_PASSWORD"}``, read through
``agent.secret_scope.get_secret`` (this workspace's own secrets). The TeamShift build has no
``op://`` path: the plugin never runs the 1Password CLI, never passes a service-account token to a
child process, and refuses ``op`` references and unresolved ``op://`` values.

wp-manager never reads or writes the ``.env`` file itself.

Resolved values are registered with :mod:`redact` so they are masked in every output.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any, Callable, Optional

from . import redact, registry

CONNECTION_PREFIX = "wpmh1:"
MAX_PASSWORD_LEN = 200


class CredentialError(Exception):
    """Credential could not be resolved / decoded. Messages never contain the secret."""


# ------------------------------------------------------------------ swappable source (tests)
def _default_secret_getter(name: str) -> Optional[str]:
    """This workspace's own secret, through the engine's profile-scoped secret route only.
    Fails closed when that route is unavailable: never a plain process-environment read."""
    try:
        from agent.secret_scope import get_secret
    except ImportError as exc:
        raise CredentialError("the workspace secret store is unavailable; no credential was read") from exc
    return get_secret(name)


SecretGetter = Callable[[str], Optional[str]]
_secret_getter: SecretGetter = _default_secret_getter


def set_secret_getter(fn: Optional[SecretGetter]) -> None:
    global _secret_getter
    _secret_getter = fn or _default_secret_getter


# ------------------------------------------------------------------ resolution
def _clean_password(value: Any) -> str:
    if not isinstance(value, str):
        raise CredentialError("credential is empty")
    v = value.strip()
    if v.lower().startswith("op://"):
        raise CredentialError("credential is an op:// reference, which this build does not resolve; store the "
                              "Application Password itself as the workspace secret")
    if not v or len(v) > MAX_PASSWORD_LEN or any(c in v for c in "\r\n\x00"):
        raise CredentialError("credential is empty or malformed")
    return v


def resolve(site: dict) -> str:
    """Return the Application Password for ``site``. Raises CredentialError (no secret in message)."""
    ref = site.get("credential") or {"env": registry.default_env_name(site["id"])}
    try:
        ref = registry.check_credential_ref(ref)
    except registry.RegistryError as exc:
        raise CredentialError(str(exc)) from exc
    name = ref["env"]
    try:
        value = _secret_getter(name)
    except CredentialError:
        raise
    except Exception as exc:  # UnscopedSecretError and friends
        raise CredentialError(f"secret {name} could not be read: {type(exc).__name__}") from exc
    if not value:
        raise CredentialError(
            f"secret {name} is not set. Save the site's WordPress Application Password (or the connector's "
            f"connection string) as the workspace secret {name}, then try again"
        )
    if isinstance(value, str) and value.strip().startswith(CONNECTION_PREFIX):
        conn = decode_connection_string(value)
        try:
            same_site = registry.normalize_url(conn["url"]) == registry.normalize_url(site["url"])
        except (KeyError, registry.RegistryError):
            same_site = False
        if not same_site or conn["user"] != site.get("username"):
            raise CredentialError(f"secret {name} holds a connection string for a different site or user")
        value = conn["app_password"]
    password = _clean_password(value)
    redact.remember(password, site.get("username"))
    return password


def where(ref: dict) -> str:
    return registry.credential_label(ref)


# ------------------------------------------------------------------ connection strings
def decode_connection_string(raw: Any) -> dict:
    """Decode ``wpmh1:<base64 JSON {v, url, user, app_password}>``. Never echoes the input."""
    if not isinstance(raw, str):
        raise CredentialError("connection string must be text")
    s = "".join(raw.split())
    if not s.startswith(CONNECTION_PREFIX):
        raise CredentialError("not a wp-manager connection string (it should start with wpmh1:)")
    payload = s[len(CONNECTION_PREFIX):]
    if not payload or len(payload) > 4096:
        raise CredentialError("connection string is empty or too long")
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.b64decode(payload.replace("-", "+").replace("_", "/"), validate=True)
        data = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise CredentialError("connection string is damaged (copy it again from Tools → TeamShift Connector)") from exc
    if not isinstance(data, dict) or str(data.get("v")) != "1":
        raise CredentialError("unsupported connection string version")
    url, user, pw = data.get("url"), data.get("user"), data.get("app_password")
    if not all(isinstance(x, str) and x.strip() for x in (url, user, pw)):
        raise CredentialError("connection string is missing url, user or app_password")
    password = _clean_password(pw)
    redact.remember(password, user.strip())
    return {"url": url.strip(), "user": user.strip(), "app_password": password}
