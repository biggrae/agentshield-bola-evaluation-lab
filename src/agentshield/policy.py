from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def can_read_document(user_id: str, document: Mapping[str, Any]) -> bool:
    """Return whether a user owns a document or is explicitly shared on it."""
    if not user_id or not isinstance(document, Mapping):
        return False
    owner_id = document.get("owner_id")
    shared_with = document.get("shared_with", ())
    if not isinstance(owner_id, str) or not isinstance(shared_with, (list, tuple, set)):
        return False
    return owner_id == user_id or user_id in shared_with


def can_write_document(user_id: str, document: Mapping[str, Any]) -> bool:
    """Only the owner may mutate or delete a document."""
    if not user_id or not isinstance(document, Mapping):
        return False
    return document.get("owner_id") == user_id
