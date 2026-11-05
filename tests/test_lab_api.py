import pytest
from lab.app import create_app


@pytest.fixture
def secure_client():
    app = create_app("secure")
    app.config.update(TESTING=True)
    return app.test_client(), app.extensions["documents"]


@pytest.fixture
def vulnerable_client():
    app = create_app("vulnerable")
    app.config.update(TESTING=True)
    return app.test_client()


def auth(user):
    return {"Authorization": f"Bearer {user}-token"}


def test_health(secure_client):
    client, _ = secure_client
    assert client.get("/health").status_code == 200


def test_missing_and_invalid_auth_are_rejected(secure_client):
    client, _ = secure_client
    assert client.get("/api/documents").status_code == 401
    assert client.get("/api/documents", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_list_is_tenant_scoped_and_does_not_leak_policy_metadata(secure_client):
    client, _ = secure_client
    response = client.get("/api/documents", headers=auth("alice"))
    assert response.status_code == 200
    docs = response.get_json()["documents"]
    assert {doc["id"] for doc in docs} == {"doc-101", "doc-103"}
    assert all("owner_id" not in doc and "shared_with" not in doc for doc in docs)


def test_owner_and_shared_user_can_read(secure_client):
    client, _ = secure_client
    assert client.get("/api/documents/doc-101", headers=auth("alice")).status_code == 200
    assert client.get("/api/documents/doc-103", headers=auth("alice")).status_code == 200


def test_cross_tenant_private_and_unknown_ids_are_indistinguishable(secure_client):
    client, _ = secure_client
    private = client.get("/api/documents/doc-102", headers=auth("alice"))
    missing = client.get("/api/documents/not-real", headers=auth("alice"))
    assert private.status_code == missing.status_code == 404
    assert private.get_json() == missing.get_json()


def test_shared_user_cannot_mutate_or_delete(secure_client):
    client, docs = secure_client
    before = docs["doc-103"]["title"]
    patch = client.patch("/api/documents/doc-103", headers=auth("alice"), json={"title": "tampered"})
    delete = client.delete("/api/documents/doc-103", headers=auth("alice"))
    assert patch.status_code == delete.status_code == 404
    assert docs["doc-103"]["title"] == before
    assert "doc-103" in docs


def test_owner_can_update_and_delete(secure_client):
    client, docs = secure_client
    response = client.patch("/api/documents/doc-101", headers=auth("alice"), json={"content": "updated"})
    assert response.status_code == 200
    assert docs["doc-101"]["content"] == "updated"
    deleted = client.delete("/api/documents/doc-101", headers=auth("alice"))
    assert deleted.status_code == 200
    assert "doc-101" not in docs


@pytest.mark.parametrize("field,value", [
    ("owner_id", "mallory"),
    ("shared_with", ["mallory"]),
])
def test_mass_assignment_is_rejected(secure_client, field, value):
    client, docs = secure_client
    response = client.patch("/api/documents/doc-101", headers=auth("alice"), json={field: value})
    assert response.status_code == 400
    assert docs["doc-101"]["owner_id"] == "alice"
    assert docs["doc-101"]["shared_with"] == []


def test_non_string_mutable_fields_rejected(secure_client):
    client, docs = secure_client
    response = client.patch("/api/documents/doc-101", headers=auth("alice"), json={"title": ["bad"]})
    assert response.status_code == 400
    assert docs["doc-101"]["title"] == "Alice private"


def test_vulnerable_mode_exposes_cross_tenant_document(vulnerable_client):
    response = vulnerable_client.get("/api/documents/doc-102", headers=auth("alice"))
    assert response.status_code == 200
