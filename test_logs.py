import pytest
import time
from store import Store
from control_service import execute


@pytest.fixture
def store(tmp_path):
    db_file = tmp_path / "test_logs.db"
    key_file = tmp_path / "test_logs.key"
    s = Store(db_path=str(db_file), key_path=str(key_file))
    yield s
    s.close()


def test_store_activity_logs(store):
    # Verify initial empty
    logs = store.get_activity_logs()
    assert logs == []

    # Insert items
    id1 = store.record_activity("CREATE_SERVER", provider="hetzner", target="cx22-test", status="success", details="Plan cx22")
    assert id1 > 0
    id2 = store.record_activity("DELETE_SERVER", provider="vultr", target="srv-99", status="success", details="Destroyed")
    assert id2 > id1
    id3 = store.record_activity("POWER_ACTION", provider="hetzner", target="cx22-test", status="failed", error="timeout")
    assert id3 > id2

    # Fetch all
    all_logs = store.get_activity_logs(limit=10)
    assert len(all_logs) == 3
    # Check ordering (newest first)
    assert all_logs[0]["action"] == "POWER_ACTION"
    assert all_logs[0]["status"] == "failed"
    assert all_logs[1]["action"] == "DELETE_SERVER"
    assert all_logs[2]["action"] == "CREATE_SERVER"

    # Filter by provider
    hetzner_logs = store.get_activity_logs(provider="hetzner")
    assert len(hetzner_logs) == 2
    assert all(l["provider"] == "hetzner" for l in hetzner_logs)

    # Filter by action
    del_logs = store.get_activity_logs(action="DELETE_SERVER")
    assert len(del_logs) == 1
    assert del_logs[0]["target"] == "srv-99"

    # Filter by status
    failed_logs = store.get_activity_logs(status="failed")
    assert len(failed_logs) == 1
    assert failed_logs[0]["error"] == "timeout"


@pytest.mark.anyio
async def test_control_service_activity_logs(store):
    store.record_activity("TEST_EVENT", provider="linode", target="lin-1", status="success", details="details 123")
    res = await execute("activity_logs", {"limit": 10}, store)
    assert "activity_logs" in res
    assert res["count"] >= 1
    assert res["activity_logs"][0]["action"] == "TEST_EVENT"


@pytest.mark.anyio
async def test_control_service_system_logs(store):
    res = await execute("system_logs", {"service": "all", "lines": 50}, store)
    assert "logs" in res
    assert isinstance(res["logs"], list)
    assert "count" in res
    assert "service" in res
