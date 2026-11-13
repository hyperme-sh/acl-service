"""Dependency-free transport source contract."""
import ast
from pathlib import Path


def test_no_shared_bus_publisher_or_log_path_remains():
    root=Path(__file__).resolve().parents[1]/'src/acl_service'
    for path in root.rglob('*.py'):
        source=path.read_text()
        for forbidden in ('get_tenant_event_publisher','PostgresEventPublisher','build_routing_consumer','service_bus_connection_string'):
            assert forbidden not in source
        assert not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='publish' for n in ast.walk(ast.parse(source)))
