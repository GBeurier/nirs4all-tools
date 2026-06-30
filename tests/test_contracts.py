"""Contract-vocabulary tests (``contracts.py``)."""

from __future__ import annotations

from nirs4all_tools import contracts


def test_fk_safe_table_order_matches_runtime() -> None:
    # Lifted verbatim from nirs4all migration.py:493 (_MIGRATION_TABLES).
    assert contracts.FK_SAFE_TABLE_ORDER == (
        "projects",
        "runs",
        "pipelines",
        "chains",
        "predictions",
        "artifacts",
        "logs",
    )


def test_workspace_v2_user_version() -> None:
    assert contracts.WORKSPACE_V2_USER_VERSION == 2


def test_empty_id_map_has_all_entities() -> None:
    id_map = contracts.empty_id_map()
    assert id_map["$id"] == contracts.ID_MAP_SCHEMA_ID
    assert id_map["schema_version"] == 1
    assert set(id_map["entities"]) == set(contracts.ID_MAP_ENTITIES)
    assert all(v == [] for v in id_map["entities"].values())


def test_build_manifest_skeleton() -> None:
    manifest = contracts.build_manifest(
        tool_version="0.0.1",
        support_window="window",
        source_path="/tmp/ws",
        source_fingerprint=None,
        source_kinds=["sqlite-workspace-v2"],
        detected_versions={"sqlite-workspace-v2": 2},
        target_kind="nirs4all-workspace-v2",
        target_schema_version=2,
    )
    assert manifest["$id"] == contracts.MANIFEST_SCHEMA_ID
    assert manifest["schema_version"] == 1
    for key in (
        "tool",
        "source",
        "target",
        "input_inventory",
        "output_inventory",
        "checksums",
        "old_to_new_ids",
        "preserved_opaque",
        "unsupported",
        "warnings",
        "environment",
    ):
        assert key in manifest
    assert manifest["tool"]["support_window"] == "window"
    assert manifest["target"]["kind"] == "nirs4all-workspace-v2"


def test_build_report_skeleton() -> None:
    report = contracts.build_report(
        status="success",
        target_kind="nirs4all-workspace-v2",
        target_path="/tmp/out",
        source_kinds=["sqlite-workspace-v2"],
    )
    assert report["$id"] == contracts.REPORT_SCHEMA_ID
    assert report["status"] == "success"
    for key in ("runs", "pipelines", "chains", "predictions", "arrays", "artifacts"):
        assert report["migrated_counts"][key] == 0


def test_environment_block_reports_python() -> None:
    env = contracts.environment_block()
    assert "python" in env
    assert env["python"]
