"""Explicit authorization and narrow scope for every operation."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime


class AuthorizationError(ValueError):
    pass


@dataclass(frozen=True)
class Authorization:
    id: str
    target: str
    action: str
    asserted_by: str
    issued_at: str

    @classmethod
    def for_own_device(cls, *, confirmed: bool, asserted_by: str,
                       action: str = "inventory.read") -> "Authorization":
        if not confirmed:
            raise AuthorizationError("Confirm that this is your device before collecting inventory")
        if not asserted_by or not asserted_by.strip():
            raise AuthorizationError("An operator name is required")
        if action not in {"inventory.read", "network.interfaces.read"}:
            raise AuthorizationError("Unsupported local action")
        return cls(str(uuid.uuid4()), "local-host", action, asserted_by.strip(),
                   datetime.now(UTC).isoformat())

    @classmethod
    def for_https_origin(cls, url: str, *, confirmed: bool, asserted_by: str) -> "Authorization":
        from .https_check import normalize_origin

        if not confirmed or not asserted_by or not asserted_by.strip():
            raise AuthorizationError("Explicit authorization and operator name are required")
        _, _, origin = normalize_origin(url)
        return cls(str(uuid.uuid4()), origin, "https.headers.read", asserted_by.strip(),
                   datetime.now(UTC).isoformat())

    def require(self, target: str, action: str) -> None:
        if self.target != target or self.action != action:
            raise AuthorizationError("Action or target is outside the authorized scope")

