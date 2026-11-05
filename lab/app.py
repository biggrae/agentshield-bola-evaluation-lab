from __future__ import annotations

import os
from copy import deepcopy
from flask import Flask, jsonify, request


SEED_DOCUMENTS = {
    "doc-101": {"id": "doc-101", "owner_id": "alice", "shared_with": [], "title": "Alice private", "content": "Synthetic Alice data"},
    "doc-102": {"id": "doc-102", "owner_id": "bob", "shared_with": [], "title": "Bob private", "content": "Synthetic Bob data"},
    "doc-103": {"id": "doc-103", "owner_id": "bob", "shared_with": ["alice"], "title": "Shared brief", "content": "Synthetic shared data"},
    "doc-104": {"id": "doc-104", "owner_id": "alice", "shared_with": ["bob"], "title": "Shared notes", "content": "Synthetic shared data"},
}
TOKENS = {"alice-token": "alice", "bob-token": "bob", "mallory-token": "mallory"}


def create_app(mode: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = False
    app.config["MODE"] = mode or os.getenv("AGENTSHIELD_MODE", "secure")
    if app.config["MODE"] not in {"secure", "vulnerable"}:
        raise ValueError("AGENTSHIELD_MODE must be 'secure' or 'vulnerable'")
    documents = deepcopy(SEED_DOCUMENTS)
    app.extensions["documents"] = documents

    def identity():
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        return TOKENS.get(header[7:])

    def hidden_not_found():
        return jsonify({"error": "not_found"}), 404

    def readable(user_id, doc):
        return doc["owner_id"] == user_id or user_id in doc["shared_with"]

    def writable(user_id, doc):
        return doc["owner_id"] == user_id

    def public_document(doc):
        return {key: doc[key] for key in ("id", "title", "content")}

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "mode": app.config["MODE"]})

    @app.get("/api/documents")
    def list_documents():
        user_id = identity()
        if user_id is None:
            return jsonify({"error": "unauthorized"}), 401
        visible = documents.values() if app.config["MODE"] == "vulnerable" else (
            doc for doc in documents.values() if readable(user_id, doc)
        )
        return jsonify({"documents": [public_document(doc) for doc in visible]})

    @app.get("/api/documents/<document_id>")
    def get_document(document_id):
        user_id = identity()
        if user_id is None:
            return jsonify({"error": "unauthorized"}), 401
        doc = documents.get(document_id)
        if doc is None or (app.config["MODE"] == "secure" and not readable(user_id, doc)):
            return hidden_not_found()
        return jsonify({"document": public_document(doc)})

    @app.patch("/api/documents/<document_id>")
    def update_document(document_id):
        user_id = identity()
        if user_id is None:
            return jsonify({"error": "unauthorized"}), 401
        doc = documents.get(document_id)
        if doc is None or not writable(user_id, doc):
            return hidden_not_found()
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not payload:
            return jsonify({"error": "invalid_payload"}), 400
        allowed = {"title", "content"}
        if set(payload) - allowed:
            return jsonify({"error": "invalid_fields"}), 400
        if any(not isinstance(value, str) for value in payload.values()):
            return jsonify({"error": "invalid_field_type"}), 400
        doc.update(payload)
        return jsonify({"document": public_document(doc)})

    @app.delete("/api/documents/<document_id>")
    def delete_document(document_id):
        user_id = identity()
        if user_id is None:
            return jsonify({"error": "unauthorized"}), 401
        doc = documents.get(document_id)
        if doc is None or not writable(user_id, doc):
            return hidden_not_found()
        del documents[document_id]
        return jsonify({"deleted": document_id})

    return app


app = create_app()

if __name__ == "__main__":
    # Local-only binding is intentional. Do not bind the vulnerable lab to a public interface.
    app.run(host="127.0.0.1", port=5000, debug=False)
