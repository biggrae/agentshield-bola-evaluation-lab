from agentshield.policy import can_read_document, can_write_document


def test_owner_can_read_and_write():
    doc = {"owner_id": "alice", "shared_with": []}
    assert can_read_document("alice", doc)
    assert can_write_document("alice", doc)


def test_shared_user_can_read_but_not_write():
    doc = {"owner_id": "bob", "shared_with": ["alice"]}
    assert can_read_document("alice", doc)
    assert not can_write_document("alice", doc)


def test_unrelated_user_cannot_read_or_write():
    doc = {"owner_id": "bob", "shared_with": []}
    assert not can_read_document("mallory", doc)
    assert not can_write_document("mallory", doc)


def test_malformed_policy_data_fails_closed():
    assert not can_read_document("alice", {"owner_id": "alice", "shared_with": "mallory"})
    assert not can_read_document("", {"owner_id": "alice", "shared_with": []})
