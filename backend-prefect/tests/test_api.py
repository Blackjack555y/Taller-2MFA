"""Pruebas de aceptación del backend (corren los flows con un Prefect efímero)."""
import os
import tempfile
import uuid

import pytest
from fastapi.testclient import TestClient

from app import repository as repo_module
from app import totp


@pytest.fixture(scope="module")
def client():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    test_repo = repo_module.SQLiteUserRepository(tmp.name)
    from app import flows, main
    flows.repository = main.repository = test_repo
    yield TestClient(main.app)
    os.unlink(tmp.name)


def login(client, username, password="secreto123"):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def enroll(client):
    username = f"u{uuid.uuid4().hex[:8]}"
    assert client.post("/auth/register", json={"username": username, "password": "secreto123"}).status_code == 201
    pre = login(client, username)["pre_auth_token"]
    setup = client.post("/auth/2fa/setup", json={"pre_auth_token": pre}).json()
    assert setup["mfa_state"] == "PENDING_VERIFICATION"
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    code = totp.totp(setup["secret"])
    act = client.post("/auth/2fa/activate", json={"pre_auth_token": pre, "code": code})
    assert act.status_code == 200, act.text
    return username, setup["secret"], {**act.json(), "code": code}


def test_pre_auth_token_cannot_open_vault(client):
    username, _, _ = enroll(client)
    pre = login(client, username)["pre_auth_token"]
    r = client.get("/api/boveda-secreta", headers={"Authorization": f"Bearer {pre}"})
    assert r.status_code == 401


def test_step_up_and_replay(client):
    username, secret, act = enroll(client)
    assert len(act["backup_codes"]) == 8

    pre = login(client, username)["pre_auth_token"]
    assert login(client, username)["mfa_state"] == "ACTIVE"
    # El código de la activación ya fue usado -> replay
    r = client.post("/auth/verify-2fa", json={"pre_auth_token": pre, "code": act["code"]})
    assert r.status_code == 409 and "ReplayAttackDetected" in r.json()["detail"]

    # El código de la ventana siguiente (C+1) sí sirve, una sola vez
    import time
    next_code = totp.totp(secret, time.time() + 30)
    r = client.post("/auth/verify-2fa", json={"pre_auth_token": pre, "code": next_code})
    assert r.status_code == 200, r.text
    assert r.json()["window"] == "C+1"
    vault = client.get("/api/boveda-secreta", headers={"Authorization": f"Bearer {r.json()['access_token']}"})
    assert vault.status_code == 200 and vault.json()["mfa_verified"] is True

    r = client.post("/auth/verify-2fa", json={"pre_auth_token": pre, "code": next_code})
    assert r.status_code == 409


def test_backup_code_single_use(client):
    username, _, act = enroll(client)
    backup = act["backup_codes"][0]
    pre = login(client, username)["pre_auth_token"]
    body = {"pre_auth_token": pre, "code": backup, "method": "backup"}
    assert client.post("/auth/verify-2fa", json=body).status_code == 200
    assert client.post("/auth/verify-2fa", json=body).status_code in (401, 409)


def test_wrong_code_rejected(client):
    username, secret, _ = enroll(client)
    pre = login(client, username)["pre_auth_token"]
    import time
    far_code = totp.totp(secret, time.time() + 300)
    r = client.post("/auth/verify-2fa", json={"pre_auth_token": pre, "code": far_code})
    assert r.status_code == 401


def test_secrets_are_masked_in_prefect(client):
    from prefect.client.orchestration import get_client
    from prefect.client.schemas.sorting import FlowRunSort

    username, _, _ = enroll(client)
    login(client, username)
    with get_client(sync_client=True) as prefect:
        runs = prefect.read_flow_runs(sort=FlowRunSort.START_TIME_DESC, limit=20)
    params = [r.parameters for r in runs if r.parameters.get("username") == username]
    assert params and params[0]["password"] == "**********"
    assert all(r.parameters.get("pre_auth_token") in (None, "**********") for r in runs)
