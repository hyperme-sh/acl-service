"""Create only an owned, disposable PostgreSQL instance; never accept a live URL."""
import subprocess
import time
import uuid
import os
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from controlplane_db.migrations import upgrade


@pytest.fixture(scope="session")
def migrated_sync_url():
    if os.environ.get("NIGHTLY_SUITE") == "acl-service-installed":
        # Infra provisions, checks and removes this job-owned loopback database.
        # Never substitute a shared TEST URL or create another host fixture.
        from sqlalchemy.engine import make_url
        if not (os.environ.get("GITHUB_ACTIONS") == "true"
                and os.environ.get("GITHUB_EVENT_NAME") == "schedule"
                and os.environ.get("INFRA_CI_RUN")):
            pytest.fail("Nightly database requires the scheduled Infra job")
        raw = os.environ.get("TEST_DATABASE_URL", "")
        url = make_url(raw)
        if url.host != "127.0.0.1" or not url.port or url.database != "postgres" or url.get_backend_name() != "postgresql":
            pytest.fail("Nightly database must be the Infra-owned loopback PostgreSQL fixture")
        upgrade(raw)
        yield raw
        return
    name = "acl-boundaries-" + uuid.uuid4().hex
    password = uuid.uuid4().hex
    subprocess.run(["docker", "run", "--detach", "--name", name,
                    "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=" + password,
                    "postgres:16-alpine"], check=True, capture_output=True)
    try:
        port = subprocess.check_output(["docker", "port", name, "5432/tcp"], text=True).strip().rsplit(":", 1)[1]
        url = f"postgresql+psycopg://postgres:{password}@127.0.0.1:{port}/postgres"
        # The image's temporary initialization server is socket-only. Probe the
        # published TCP endpoint used by migrations, not an in-container socket.
        probe = create_engine(url, connect_args={"connect_timeout": 1})
        try:
            deadline = time.monotonic() + 60
            while True:
                try:
                    with probe.connect() as connection:
                        connection.execute(text("SELECT 1"))
                    break
                except OperationalError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Disposable PostgreSQL TCP endpoint did not become ready") from None
                    time.sleep(1)
        finally:
            probe.dispose()
        upgrade(url)
        yield url
    finally:
        subprocess.run(["docker", "rm", "--force", "--volumes", name], check=True, capture_output=True)


@pytest.fixture(scope="session")
def seed(migrated_sync_url):
    engine = create_engine(migrated_sync_url)
    data = SimpleNamespace(ta=uuid.uuid4(), tb=uuid.uuid4())
    try:
        with engine.begin() as cx:
            for tenant in (data.ta, data.tb):
                cx.execute(text("INSERT INTO tenants (id, name, is_active) VALUES (:id, :name, true)"),
                           {"id": tenant, "name": str(tenant)})
        yield data
    finally:
        engine.dispose()
