"""Tests for Docker Compose file — Story 2.1."""

from __future__ import annotations

from pathlib import Path

import yaml


def _load_compose() -> dict:
    compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
    with open(compose_path) as f:
        return yaml.safe_load(f)


class TestInfrastructureServices:
    def test_kafka_service(self):
        data = _load_compose()
        assert "kafka" in data["services"]
        svc = data["services"]["kafka"]
        assert "redpanda" in svc["image"]
        assert "9092:9092" in svc["ports"]

    def test_postgres_service(self):
        data = _load_compose()
        svc = data["services"]["postgres"]
        assert "postgres:16" in svc["image"]
        assert svc["environment"]["POSTGRES_DB"] == "aluskort"
        assert "5432:5432" in svc["ports"]

    def test_redis_service(self):
        data = _load_compose()
        svc = data["services"]["redis"]
        assert "redis" in svc["image"]
        assert "6379:6379" in svc["ports"]

    def test_qdrant_service(self):
        data = _load_compose()
        svc = data["services"]["qdrant"]
        assert "qdrant" in svc["image"]
        assert "6333:6333" in svc["ports"]

    def test_neo4j_service(self):
        data = _load_compose()
        svc = data["services"]["neo4j"]
        assert "neo4j" in svc["image"]
        assert "7474:7474" in svc["ports"]
        assert "7687:7687" in svc["ports"]

    def test_minio_service(self):
        data = _load_compose()
        svc = data["services"]["minio"]
        assert "minio" in svc["image"]
        assert "9000:9000" in svc["ports"]
        assert "9001:9001" in svc["ports"]


class TestDataPersistence:
    def test_volumes_defined(self):
        data = _load_compose()
        vols = data["volumes"]
        assert "pgdata" in vols
        assert "qdrantdata" in vols
        assert "neo4jdata" in vols

    def test_postgres_uses_volume(self):
        data = _load_compose()
        svc = data["services"]["postgres"]
        vol_mounts = [v for v in svc["volumes"] if "pgdata" in v]
        assert len(vol_mounts) == 1

    def test_postgres_loads_migrations(self):
        data = _load_compose()
        svc = data["services"]["postgres"]
        migration_mounts = [v for v in svc["volumes"] if "migrations" in v]
        assert len(migration_mounts) == 1


class TestAluskortServices:
    def test_migration_job_runs_for_persistent_databases(self):
        data = _load_compose()
        migrate = data["services"]["migrate"]
        assert migrate["build"]["dockerfile"] == "Dockerfile.migrate"
        assert migrate["command"] == ["python", "-m", "infra.scripts.apply_migrations"]
        assert migrate["depends_on"]["postgres"]["condition"] == "service_healthy"
        for service in ["dashboard", "sentinel-adapter", "sentinel-writeback"]:
            assert (
                data["services"][service]["depends_on"]["migrate"]["condition"]
                == "service_completed_successfully"
            )

    def test_entity_parser_depends_on_infra(self):
        data = _load_compose()
        svc = data["services"]["entity-parser"]
        deps = svc["depends_on"]
        assert "kafka" in deps
        assert "postgres" in deps

    def test_orchestrator_depends_on_all(self):
        data = _load_compose()
        svc = data["services"]["orchestrator"]
        deps = svc["depends_on"]
        assert "kafka" in deps
        assert "postgres" in deps
        assert "qdrant" in deps
        assert "redis" in deps
        assert "neo4j" in deps

    def test_context_gateway_has_anthropic_key(self):
        data = _load_compose()
        svc = data["services"]["context-gateway"]
        assert "ANTHROPIC_API_KEY" in svc["environment"]

    def test_services_use_profiles(self):
        data = _load_compose()
        for name in ["entity-parser", "context-gateway", "llm-router", "orchestrator", "ctem-normaliser"]:
            svc = data["services"][name]
            assert "profiles" in svc
            assert "services" in svc["profiles"]


class TestHealthChecks:
    def test_infra_services_have_healthchecks(self):
        data = _load_compose()
        for name in ["kafka", "postgres", "redis", "qdrant", "neo4j"]:
            svc = data["services"][name]
            assert "healthcheck" in svc, f"{name} missing healthcheck"
