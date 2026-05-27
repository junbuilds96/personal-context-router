import json
import os
from hashlib import sha256
from pathlib import Path
import subprocess
import sys

import pytest

from personal_context_router import __version__
from personal_context_router.core import (
    ApprovalRequired,
    InvalidPipelineInput,
    REDACTION_MARKER,
    approve_signals,
    create_packet,
    create_request,
    create_writeback,
    diagnose_packet,
    doctor_workdir,
    extract_signals,
    packet_stats,
    packet_stats_json_text,
    packet_stats_text,
    redact_content,
    redact_file,
    run_route,
    run_sample,
    serialize_context_packet_json,
)


def test_redaction_handles_common_sensitive_patterns():
    raw = "\n".join(
        [
            "Email: person@example.com",
            "Phone: +1 (555) 010-0199",
            "api_key = should-not-survive",
            "hash: 0123456789abcdef0123456789abcdef",
            "Keep this project goal.",
        ]
    )

    redacted = redact_content(raw)

    assert "person@example.com" not in redacted
    assert "555" not in redacted
    assert "should-not-survive" not in redacted
    assert "0123456789abcdef0123456789abcdef" not in redacted
    assert redacted.count(REDACTION_MARKER) >= 4
    assert "Keep this project goal." in redacted


def test_approve_requires_explicit_gate(tmp_path: Path):
    signals = tmp_path / "signals.md"
    signals.write_text("---\ntype: context_signals\n---\n\n# Signals\n", encoding="utf-8")

    with pytest.raises(ApprovalRequired, match="--approve-all"):
        approve_signals(signals, tmp_path / "approved.md", approve_all=False)


def test_approve_selects_signal_bullets_by_index(tmp_path: Path):
    signals = tmp_path / "signals.md"
    signals.write_text(
        "\n".join(
            [
                "---",
                "type: context_signals",
                "---",
                "",
                "# Context Signals",
                "",
                "## Goals",
                "- Safety constraints:",
                "- First useful signal.",
                "- Second useful signal.",
                "",
                "## Agent Needs",
                "- Third useful signal.",
            ]
        ),
        encoding="utf-8",
    )

    approved = approve_signals(
        signals,
        tmp_path / "approved.md",
        approve_all=False,
        select="1,3",
    )

    assert "approval: select" in approved.text
    assert "Approval mode: select" in approved.text
    assert "Selected indexes: 1,3" in approved.text
    assert "Rejected indexes: none" in approved.text
    assert "Total selectable signals: 3" in approved.text
    assert "- Safety constraints:" not in approved.text
    assert "- First useful signal." in approved.text
    assert "- Second useful signal." not in approved.text
    assert "- Third useful signal." in approved.text


def test_approve_rejects_signal_bullets_by_index(tmp_path: Path):
    signals = tmp_path / "signals.md"
    signals.write_text(
        "\n".join(
            [
                "---",
                "type: context_signals",
                "---",
                "",
                "# Context Signals",
                "",
                "## Goals",
                "- First useful signal.",
                "- Second useful signal.",
                "- Third useful signal.",
            ]
        ),
        encoding="utf-8",
    )

    approved = approve_signals(
        signals,
        tmp_path / "approved.md",
        approve_all=False,
        reject="2",
    )

    assert "approval: reject" in approved.text
    assert "Approval mode: reject" in approved.text
    assert "Selected indexes: 1,3" in approved.text
    assert "Rejected indexes: 2" in approved.text
    assert "Total selectable signals: 3" in approved.text
    assert "- First useful signal." in approved.text
    assert "- Second useful signal." not in approved.text
    assert "- Third useful signal." in approved.text


@pytest.mark.parametrize(
    ("selection", "message"),
    [
        ("0", "must be 1 or greater"),
        ("-1", "must be 1 or greater"),
        ("two", "not an integer"),
        ("4", "out of range"),
        ("1,1", "duplicated"),
    ],
)
def test_approve_select_fails_invalid_indexes(tmp_path: Path, selection: str, message: str):
    signals = tmp_path / "signals.md"
    signals.write_text(
        "---\ntype: context_signals\n---\n\n# Context Signals\n\n- First\n- Second\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=message):
        approve_signals(
            signals,
            tmp_path / "approved.md",
            approve_all=False,
            select=selection,
        )


def test_packet_creation_accepts_subset_approval(tmp_path: Path):
    signals = tmp_path / "signals.md"
    signals.write_text(
        "---\ntype: context_signals\n---\n\n# Context Signals\n\n- Keep this signal.\n- Drop this signal.\n",
        encoding="utf-8",
    )
    approved = approve_signals(
        signals,
        tmp_path / "approved.md",
        approve_all=False,
        select="1",
    )

    packet = create_packet(
        approved.path,
        agent="qa-agent",
        task="verify selected context",
        output_path=tmp_path / "packet.md",
    )
    diagnostics = diagnose_packet(packet.path, tmp_path / "diagnostics.md")

    assert "type: context_packet" in packet.text
    assert "Approval mode: select" in packet.text
    assert "- Keep this signal." in packet.text
    assert "- Drop this signal." not in packet.text
    assert diagnostics.passed is True


def test_serialize_context_packet_json_serializes_stable_packet_fields(tmp_path: Path):
    signals = tmp_path / "signals.md"
    signals.write_text(
        "---\ntype: context_signals\n---\n\n# Context Signals\n\n- Keep this signal.\n",
        encoding="utf-8",
    )
    approved = approve_signals(
        signals,
        tmp_path / "approved.md",
        approve_all=False,
        select="1",
    )
    packet = create_packet(
        approved.path,
        agent="qa-agent",
        task="verify JSON packet export",
        output_path=tmp_path / "packet.md",
    )

    data = json.loads(serialize_context_packet_json(packet.path))

    assert list(data) == [
        "schema",
        "type",
        "agent",
        "task",
        "approved_digest",
        "packet_digest",
        "source_filename",
        "approved_context",
    ]
    assert data["schema"] == "pcr.context_packet.v1"
    assert data["type"] == "context_packet"
    assert data["agent"] == "qa-agent"
    assert data["task"] == "verify JSON packet export"
    assert data["approved_digest"]
    assert data["packet_digest"] == sha256(packet.text.encode("utf-8")).hexdigest()[:16]
    assert data["source_filename"] == "packet.md"
    assert "Approval mode: select" in data["approved_context"]
    assert "- Keep this signal." in data["approved_context"]


def test_packet_creation_writes_json_when_requested(tmp_path: Path):
    signals = tmp_path / "signals.md"
    signals.write_text(
        "---\ntype: context_signals\n---\n\n# Context Signals\n\n- Keep this signal.\n",
        encoding="utf-8",
    )
    approved = approve_signals(
        signals,
        tmp_path / "approved.md",
        approve_all=False,
        select="1",
    )
    json_packet = tmp_path / "packet.json"

    packet = create_packet(
        approved.path,
        agent="qa-agent",
        task="write JSON packet artifact",
        output_path=tmp_path / "packet.md",
        json_output_path=json_packet,
    )

    data = json.loads(json_packet.read_text(encoding="utf-8"))
    assert packet.path.exists()
    assert data["schema"] == "pcr.context_packet.v1"
    assert data["source_filename"] == "packet.md"
    assert data["packet_digest"] == sha256(packet.text.encode("utf-8")).hexdigest()[:16]


def test_packet_request_writeback_pipeline(tmp_path: Path):
    source = tmp_path / "note.md"
    source.write_text(
        "Goal: build a demo.\nContact: demo@example.test\napi_key = fake-value\n",
        encoding="utf-8",
    )

    redact_file(source, tmp_path / "redacted.md")
    extract_signals(tmp_path / "redacted.md", "unit-test", tmp_path / "signals.md")
    approve_signals(tmp_path / "signals.md", tmp_path / "approved.md", approve_all=True)
    packet = create_packet(
        tmp_path / "approved.md",
        agent="qa-agent",
        task="verify audit trail",
        output_path=tmp_path / "packet.md",
    )
    request = create_request(packet.path, tmp_path / "request.md")
    writeback = create_writeback(
        request.path,
        tmp_path / "writeback.md",
        status="sufficient",
        note="Enough context for test.",
        decision_out=tmp_path / "decision.md",
    )

    assert "type: context_packet" in packet.text
    assert "agent: qa-agent" in packet.text
    assert "type: context_request" in request.text
    assert "Packet digest:" in request.text
    assert "type: writeback" in writeback.text
    assert "Status: sufficient" in writeback.text
    assert (tmp_path / "decision.md").exists()


def test_diagnose_packet_passes_valid_packet(tmp_path: Path):
    source = tmp_path / "note.md"
    source.write_text("Goal: build a demo.\n", encoding="utf-8")

    redact_file(source, tmp_path / "redacted.md")
    extract_signals(tmp_path / "redacted.md", "unit-test", tmp_path / "signals.md")
    approve_signals(tmp_path / "signals.md", tmp_path / "approved.md", approve_all=True)
    packet = create_packet(
        tmp_path / "approved.md",
        agent="qa-agent",
        task="verify diagnostics",
        output_path=tmp_path / "packet.md",
    )

    diagnostics = diagnose_packet(packet.path, tmp_path / "diagnostics.md")

    assert diagnostics.passed is True
    assert "type: packet_diagnostics" in diagnostics.artifact.text
    assert "overall: pass" in diagnostics.artifact.text
    assert "| artifact type is context_packet | PASS | type=context_packet |" in diagnostics.artifact.text
    assert "| task is scoped | PASS | task is scoped |" in diagnostics.artifact.text
    assert "| approved_digest is present and formatted | PASS | approved_digest is a 16-character lowercase hex digest |" in diagnostics.artifact.text
    assert "| approved context section present | PASS | ## Approved Context heading found |" in diagnostics.artifact.text


def test_diagnose_packet_writes_passing_json_diagnostics(tmp_path: Path):
    source = tmp_path / "note.md"
    source.write_text("Goal: build a demo.\n", encoding="utf-8")

    redact_file(source, tmp_path / "redacted.md")
    extract_signals(tmp_path / "redacted.md", "unit-test", tmp_path / "signals.md")
    approve_signals(tmp_path / "signals.md", tmp_path / "approved.md", approve_all=True)
    packet = create_packet(
        tmp_path / "approved.md",
        agent="qa-agent",
        task="verify diagnostics",
        output_path=tmp_path / "packet.md",
    )

    diagnostics = diagnose_packet(
        packet.path,
        tmp_path / "diagnostics.md",
        tmp_path / "diagnostics.json",
    )

    assert diagnostics.passed is True
    assert diagnostics.json_artifact is not None
    data = json.loads(diagnostics.json_artifact.text)
    assert data["schema"] == "pcr.diagnostics.v1"
    assert data["type"] == "packet_diagnostics"
    assert data["packet_filename"] == "packet.md"
    assert data["packet_digest"]
    assert data["overall"] == "pass"
    assert data["counts"] == {"total": 18, "passed": 18, "failed": 0}
    assert data["leaks"]["total"] == 0
    assert data["leaks"]["counts_by_category"] == {
        "credential": 0,
        "email_address": 0,
        "phone_like": 0,
        "long_hex": 0,
        "local_path": 0,
        "redaction_marker": 0,
    }
    assert data["checks"][0] == {
        "name": "frontmatter present",
        "result": "pass",
        "detail": "frontmatter found",
    }
    assert "Goal: build a demo." not in diagnostics.json_artifact.text


def test_diagnose_packet_fails_invalid_packet(tmp_path: Path):
    packet = tmp_path / "packet.md"
    packet.write_text(
        "\n".join(
            [
                "---",
                "type: context_signals",
                "agent: qa-agent",
                "---",
                "",
                "# Context Packet",
                "",
                "## Scope",
                "- marker leaked: [REDACTED]",
            ]
        ),
        encoding="utf-8",
    )

    diagnostics = diagnose_packet(packet, tmp_path / "diagnostics.md")

    assert diagnostics.passed is False
    assert "overall: fail" in diagnostics.artifact.text
    assert "| artifact type is context_packet | FAIL | expected type=context_packet; found context_signals |" in diagnostics.artifact.text
    assert "| task is scoped | FAIL | task is missing or empty |" in diagnostics.artifact.text
    assert "| approved_digest is present and formatted | FAIL | approved_digest is missing or empty |" in diagnostics.artifact.text
    assert "| no redaction marker leaked | FAIL | redaction marker found |" in diagnostics.artifact.text
    assert "| approved context section present | FAIL | ## Approved Context heading missing |" in diagnostics.artifact.text


def test_diagnose_packet_writes_failing_json_diagnostics(tmp_path: Path):
    packet = tmp_path / "packet.md"
    packet.write_text(
        "\n".join(
            [
                "---",
                "type: context_signals",
                "agent: qa-agent",
                "---",
                "",
                "# Context Packet",
                "",
                "## Scope",
                "- marker leaked: [REDACTED]",
            ]
        ),
        encoding="utf-8",
    )

    diagnostics = diagnose_packet(
        packet,
        tmp_path / "diagnostics.md",
        tmp_path / "diagnostics.json",
    )

    assert diagnostics.passed is False
    assert diagnostics.json_artifact is not None
    data = json.loads(diagnostics.json_artifact.text)
    assert data["overall"] == "fail"
    assert data["counts"]["total"] == 18
    assert data["counts"]["passed"] < 13
    assert data["counts"]["failed"] > 0
    assert {
        "name": "artifact type is context_packet",
        "result": "fail",
        "detail": "expected type=context_packet; found context_signals",
    } in data["checks"]
    assert {
        "name": "no redaction marker leaked",
        "result": "fail",
        "detail": "redaction marker found",
    } in data["checks"]


def test_packet_stats_summarizes_packet_without_raw_context(tmp_path: Path):
    signals = tmp_path / "signals.md"
    raw_context = "Keep this uniquely sensitive approved signal."
    signals.write_text(
        f"---\ntype: context_signals\n---\n\n# Context Signals\n\n- {raw_context}\n",
        encoding="utf-8",
    )
    approved = approve_signals(
        signals,
        tmp_path / "approved.md",
        approve_all=False,
        select="1",
    )
    packet = create_packet(
        approved.path,
        agent="qa-agent",
        task="verify packet stats summary",
        output_path=tmp_path / "packet.md",
    )

    stats = packet_stats(packet.path)
    text = packet_stats_text(stats)
    json_text = packet_stats_json_text(stats)
    data = json.loads(json_text)

    assert stats.packet_filename == "packet.md"
    assert stats.packet_digest == sha256(packet.text.encode("utf-8")).hexdigest()[:16]
    assert stats.agent == "qa-agent"
    assert stats.task == "verify packet stats summary"
    assert stats.total_characters == len(packet.text)
    assert stats.approved_context_characters == len(
        packet.text.split("## Approved Context", 1)[1].strip()
    )
    assert stats.approximate_tokens == (len(packet.text) + 3) // 4
    assert stats.diagnostic_passed is True
    assert stats.diagnostic_total == 18
    assert stats.diagnostic_failed_count == 0
    assert raw_context not in text
    assert raw_context not in json_text
    assert data["schema"] == "pcr.packet_stats.v1"
    assert data["characters"] == {
        "total": len(packet.text),
        "approved_context": stats.approved_context_characters,
    }
    assert data["diagnostics"]["counts"] == {"total": 18, "passed": 18, "failed": 0}
    assert data["leaks"]["total"] == 0
    assert data["leaks"]["counts_by_category"] == {
        "credential": 0,
        "email_address": 0,
        "phone_like": 0,
        "long_hex": 0,
        "local_path": 0,
        "redaction_marker": 0,
    }


def test_packet_diagnostics_detects_synthetic_leaks(tmp_path: Path):
    packet = tmp_path / "packet.md"
    packet.write_text(
        "\n".join(
            [
                "---",
                "type: context_packet",
                "agent: qa-agent",
                "task: inspect synthetic leaks",
                "approved_digest: abcdef1234567890",
                "---",
                "",
                "# Context Packet",
                "",
                "Agent: qa-agent",
                "Task: inspect synthetic leaks",
                "Approved source digest: abcdef1234567890",
                "",
                "## Scope",
                "- Use this packet only for the named task.",
                "",
                "## Approved Context",
                "- api_key = synthetic-demo-value",
                "- contact synthetic@example.test",
                "- phone +1 555 010 9999",
                "- hex 0123456789abcdef0123456789abcdef",
                "- unix path /home/demo/project",
                r"- windows path C:\Users\demo\project",
                "- marker [REDACTED]",
            ]
        ),
        encoding="utf-8",
    )

    diagnostics = diagnose_packet(packet, tmp_path / "diagnostics.md", tmp_path / "diagnostics.json")

    assert diagnostics.passed is False
    data = json.loads((tmp_path / "diagnostics.json").read_text(encoding="utf-8"))
    counts = data["leaks"]["counts_by_category"]
    assert data["leaks"]["total"] >= 6
    assert counts["credential"] >= 1
    assert counts["email_address"] >= 1
    assert counts["phone_like"] >= 1
    assert counts["long_hex"] >= 1
    assert counts["local_path"] >= 2
    assert counts["redaction_marker"] >= 1


def test_packet_stats_rejects_non_packet_input(tmp_path: Path):
    signals = tmp_path / "signals.md"
    signals.write_text(
        "---\ntype: context_signals\n---\n\n# Context Signals\n\n- Not a packet.\n",
        encoding="utf-8",
    )

    with pytest.raises(InvalidPipelineInput, match="requires a context packet"):
        packet_stats(signals)


def test_extract_signals_skips_redacted_lines_and_section_labels(tmp_path: Path):
    redacted = tmp_path / "redacted.md"
    redacted.write_text(
        "\n".join(
            [
                "# Redacted Source",
                "",
                "Safety constraints:",
                "- Contact: [REDACTED]",
                "- Redact private details before approval.",
                "",
                "Agent needs:",
                "- cli-agent needs command examples.",
                "- request came from [REDACTED]",
            ]
        ),
        encoding="utf-8",
    )

    signals = extract_signals(redacted, "unit-test", tmp_path / "signals.md")

    assert "[REDACTED]" not in signals.text
    assert "- Safety constraints:" not in signals.text
    assert "- Agent needs:" not in signals.text
    assert "- Redact private details before approval." in signals.text
    assert "- cli-agent needs command examples." in signals.text


def test_run_sample_creates_complete_demo(tmp_path: Path):
    artifacts = run_sample(tmp_path)

    names = [artifact.path.name for artifact in artifacts]
    assert names == [
        "sample-note.md",
        "01-redacted.md",
        "02-signals.md",
        "03-approved.md",
        "04-packet.md",
        "05-diagnostics.md",
        "06-request.md",
        "07-writeback.md",
    ]
    assert (tmp_path / "08-decision.md").exists()
    packet = (tmp_path / "04-packet.md").read_text(encoding="utf-8")
    assert "type: context_packet" in packet
    assert "[REDACTED]" not in packet
    assert "- Safety constraints:" not in packet
    assert "- Agent needs:" not in packet
    for name in ("02-signals.md", "03-approved.md", "04-packet.md", "05-diagnostics.md"):
        generated = (tmp_path / name).read_text(encoding="utf-8")
        assert "\n        #" not in generated
        assert "\n        -" not in generated


def test_doctor_workdir_passes_run_sample_workdir(tmp_path: Path):
    run_sample(tmp_path)

    result = doctor_workdir(tmp_path)

    assert result.passed is True
    assert result.artifact is None
    assert "**Overall:** pass" in result.report_text
    assert "| artifact exists: 05-diagnostics.md | PASS | found |" in result.report_text
    assert "| artifact type: 08-decision.md | PASS | type=routing_decision |" in result.report_text
    assert "| packet diagnostics pass | PASS | 18/18 packet checks passed |" in result.report_text
    assert "| handoff leak scan: 04-packet.md | PASS | no obvious leaks found |" in result.report_text


def test_doctor_workdir_passes_route_workdir_and_writes_json(tmp_path: Path):
    note = tmp_path / "note.md"
    workdir = tmp_path / "route"
    json_report = tmp_path / "doctor.json"
    note.write_text(
        "\n".join(
            [
                "Goal: build the route command.",
                "docs-agent needs a concise CLI example.",
                "Contact: route-demo@example.test",
                "api_key = fake-value",
            ]
        ),
        encoding="utf-8",
    )
    route = run_route(
        note,
        source="unit-route-note",
        agent="docs-agent",
        task="draft route command docs",
        workdir=workdir,
        approve_all=True,
    )
    assert route.diagnostics.passed is True

    result = doctor_workdir(workdir, json_output_path=json_report)

    assert result.passed is True
    assert result.json_artifact is not None
    data = json.loads(json_report.read_text(encoding="utf-8"))
    assert data["schema"] == "pcr.doctor.v1"
    assert data["overall"] == "pass"
    assert data["workdir"] == str(workdir)
    assert data["workdir_basename"] == "route"
    assert data["counts"]["failed"] == 0
    assert {
        "name": "artifact type: 06-request.md",
        "result": "pass",
        "detail": "type=context_request",
    } in data["checks"]


def test_doctor_workdir_fails_missing_artifact_and_handoff_leak(tmp_path: Path):
    run_sample(tmp_path)
    (tmp_path / "06-request.md").unlink()
    packet = tmp_path / "04-packet.md"
    packet.write_text(
        packet.read_text(encoding="utf-8") + "\nContact: leaked@example.test\n",
        encoding="utf-8",
    )

    result = doctor_workdir(tmp_path)

    assert result.passed is False
    assert "| artifact exists: 06-request.md | FAIL | missing |" in result.report_text
    assert "| handoff leak scan: 04-packet.md | FAIL | found email address |" in result.report_text


def test_cli_approve_gate_fails_nonzero(tmp_path: Path):
    signals = tmp_path / "signals.md"
    signals.write_text("---\ntype: context_signals\n---\n\n# Signals\n", encoding="utf-8")
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "approve",
            str(signals),
            "--out",
            str(tmp_path / "approved.md"),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 2
    assert "--approve-all" in result.stderr
    assert "--select" in result.stderr
    assert "--reject" in result.stderr


def test_cli_approve_select_writes_subset(tmp_path: Path):
    signals = tmp_path / "signals.md"
    approved = tmp_path / "approved.md"
    signals.write_text(
        "---\ntype: context_signals\n---\n\n# Context Signals\n\n- First\n- Second\n- Third\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "approve",
            str(signals),
            "--select",
            "1,3",
            "--out",
            str(approved),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    text = approved.read_text(encoding="utf-8")
    assert result.returncode == 0
    assert "Wrote" in result.stdout
    assert "Approval mode: select" in text
    assert "- First" in text
    assert "- Second" not in text
    assert "- Third" in text


def test_cli_approve_reject_and_approve_all_are_mutually_exclusive(tmp_path: Path):
    signals = tmp_path / "signals.md"
    signals.write_text(
        "---\ntype: context_signals\n---\n\n# Context Signals\n\n- First\n- Second\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "approve",
            str(signals),
            "--approve-all",
            "--reject",
            "2",
            "--out",
            str(tmp_path / "approved.md"),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 2
    assert "not allowed with argument" in result.stderr


def test_cli_packet_writes_json_when_requested(tmp_path: Path):
    approved = tmp_path / "approved.md"
    packet = tmp_path / "packet.md"
    json_packet = tmp_path / "packet.json"
    approved.write_text(
        "\n".join(
            [
                "---",
                "type: approved_signals",
                "approval: approve-all",
                "---",
                "",
                "# Approved Context Signals",
                "",
                "Approval mode: approve-all",
                "Selected indexes: 1",
                "Rejected indexes: none",
                "Total selectable signals: 1",
                "",
                "- Keep this signal.",
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "packet",
            str(approved),
            "--agent",
            "qa-agent",
            "--task",
            "verify JSON packet export",
            "--out",
            str(packet),
            "--json-out",
            str(json_packet),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    data = json.loads(json_packet.read_text(encoding="utf-8"))
    assert result.returncode == 0
    assert f"Wrote {packet}" in result.stdout
    assert packet.exists()
    assert data["schema"] == "pcr.context_packet.v1"
    assert data["type"] == "context_packet"
    assert data["source_filename"] == "packet.md"
    assert data["approved_context"].endswith("- Keep this signal.")


def test_cli_packet_json_invalid_input_writes_no_outputs(tmp_path: Path):
    signals = tmp_path / "signals.md"
    packet = tmp_path / "packet.md"
    json_packet = tmp_path / "packet.json"
    signals.write_text(
        "---\ntype: context_signals\n---\n\n# Context Signals\n\n- Not approved yet.\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "packet",
            str(signals),
            "--agent",
            "qa-agent",
            "--task",
            "verify JSON packet export",
            "--out",
            str(packet),
            "--json-out",
            str(json_packet),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 2
    assert "requires an approved signals artifact" in result.stderr
    assert not packet.exists()
    assert not json_packet.exists()


def test_cli_stats_prints_safe_text_summary(tmp_path: Path):
    signals = tmp_path / "signals.md"
    raw_context = "Keep this private implementation detail out of stats output."
    signals.write_text(
        f"---\ntype: context_signals\n---\n\n# Context Signals\n\n- {raw_context}\n",
        encoding="utf-8",
    )
    approved = approve_signals(
        signals,
        tmp_path / "approved.md",
        approve_all=False,
        select="1",
    )
    packet = create_packet(
        approved.path,
        agent="qa-agent",
        task="verify stats command output",
        output_path=tmp_path / "packet.md",
    )
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "stats",
            str(packet.path),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout.startswith("Packet stats\n")
    assert "Packet: packet.md\n" in result.stdout
    assert "Digest:" in result.stdout
    assert "Agent: qa-agent\n" in result.stdout
    assert "Task: verify stats command output\n" in result.stdout
    assert "Characters:" in result.stdout
    assert "Approx tokens:" in result.stdout
    assert "Diagnostics: pass (18/18 passed, 0 failed)\n" in result.stdout
    assert raw_context not in result.stdout


def test_cli_stats_prints_safe_json_only(tmp_path: Path):
    signals = tmp_path / "signals.md"
    raw_context = "Keep this hidden from JSON stats."
    signals.write_text(
        f"---\ntype: context_signals\n---\n\n# Context Signals\n\n- {raw_context}\n",
        encoding="utf-8",
    )
    approved = approve_signals(
        signals,
        tmp_path / "approved.md",
        approve_all=False,
        select="1",
    )
    packet = create_packet(
        approved.path,
        agent="qa-agent",
        task="verify stats JSON output",
        output_path=tmp_path / "packet.md",
    )
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "stats",
            str(packet.path),
            "--json",
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    data = json.loads(result.stdout)
    assert result.returncode == 0
    assert result.stderr == ""
    assert data["schema"] == "pcr.packet_stats.v1"
    assert data["packet_filename"] == "packet.md"
    assert data["packet_digest"] == sha256(packet.text.encode("utf-8")).hexdigest()[:16]
    assert data["agent"] == "qa-agent"
    assert data["task"] == "verify stats JSON output"
    assert data["characters"]["total"] == len(packet.text)
    assert data["approximate_tokens"] == (len(packet.text) + 3) // 4
    assert data["diagnostics"]["overall"] == "pass"
    assert data["diagnostics"]["counts"] == {"total": 18, "passed": 18, "failed": 0}
    assert raw_context not in result.stdout


def test_cli_stats_rejects_non_packet_input(tmp_path: Path):
    signals = tmp_path / "signals.md"
    signals.write_text(
        "---\ntype: context_signals\n---\n\n# Context Signals\n\n- Not a packet.\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "stats",
            str(signals),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr.startswith("pcr: error:")
    assert "Packet stats requires a context packet." in result.stderr


def test_cli_diagnose_fails_nonzero_and_writes_report(tmp_path: Path):
    packet = tmp_path / "packet.md"
    report = tmp_path / "diagnostics.md"
    json_report = tmp_path / "diagnostics.json"
    packet.write_text("---\ntype: context_packet\n---\n\n# Packet\n", encoding="utf-8")
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "diagnose",
            str(packet),
            "--out",
            str(report),
            "--json-out",
            str(json_report),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 1
    assert f"Wrote {report}" in result.stdout
    assert "Diagnostics: fail" in result.stdout
    assert str(json_report) not in result.stdout
    assert report.exists()
    assert "overall: fail" in report.read_text(encoding="utf-8")
    assert json_report.exists()
    assert json.loads(json_report.read_text(encoding="utf-8"))["overall"] == "fail"


def test_cli_doctor_fails_nonzero_and_writes_reports(tmp_path: Path):
    run_sample(tmp_path)
    (tmp_path / "05-diagnostics.md").unlink()
    report = tmp_path / "doctor.md"
    json_report = tmp_path / "doctor.json"
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "doctor",
            str(tmp_path),
            "--out",
            str(report),
            "--json-out",
            str(json_report),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 1
    assert f"Wrote {report}" in result.stdout
    assert "Doctor: fail" in result.stdout
    assert report.exists()
    assert "| artifact exists: 05-diagnostics.md | FAIL | missing |" in report.read_text(
        encoding="utf-8"
    )
    assert json.loads(json_report.read_text(encoding="utf-8"))["overall"] == "fail"


def test_cli_doctor_prints_report_to_stdout(tmp_path: Path):
    run_sample(tmp_path)
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "doctor",
            str(tmp_path),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0
    assert result.stdout.startswith("# PCR Doctor Report\n")
    assert "**Overall:** pass" in result.stdout
    assert "Doctor: pass" not in result.stdout


def test_cli_route_success_writes_pipeline_artifacts_and_json(tmp_path: Path):
    note = tmp_path / "note.md"
    workdir = tmp_path / "route"
    packet_json = tmp_path / "packet.json"
    diagnostics_json = tmp_path / "diagnostics.json"
    note.write_text(
        "\n".join(
            [
                "Goal: build the route command.",
                "docs-agent needs a concise CLI example.",
                "Contact: route-demo@example.test",
                "api_key = fake-value",
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "route",
            str(note),
            "--source",
            "unit-route-note",
            "--agent",
            "docs-agent",
            "--task",
            "draft route command docs",
            "--workdir",
            str(workdir),
            "--approve-all",
            "--json-out",
            str(packet_json),
            "--diagnostics-json-out",
            str(diagnostics_json),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0
    assert "Wrote route artifacts:" in result.stdout
    assert "Diagnostics: pass" in result.stdout
    assert [path.name for path in sorted(workdir.iterdir())] == [
        "01-redacted.md",
        "02-signals.md",
        "03-approved.md",
        "04-packet.md",
        "05-diagnostics.md",
        "06-request.md",
    ]
    packet = (workdir / "04-packet.md").read_text(encoding="utf-8")
    assert "type: context_packet" in packet
    assert "agent: docs-agent" in packet
    assert "route-demo@example.test" not in packet
    assert "fake-value" not in packet
    assert "[REDACTED]" not in packet
    assert json.loads(packet_json.read_text(encoding="utf-8"))["schema"] == "pcr.context_packet.v1"
    assert json.loads(diagnostics_json.read_text(encoding="utf-8"))["overall"] == "pass"


def test_cli_route_diagnostics_failure_does_not_write_request(tmp_path: Path):
    note = tmp_path / "note.md"
    workdir = tmp_path / "route"
    note.write_text(
        "\n".join(
            [
                "Goal: build the route command.",
                "Should docs-agent email route-demo@example.test?",
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "route",
            str(note),
            "--source",
            "unit-route-note",
            "--agent",
            "docs-agent",
            "--task",
            "draft route command docs",
            "--workdir",
            str(workdir),
            "--approve-all",
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 1
    assert "Wrote route artifacts:" in result.stdout
    assert "Diagnostics: fail" in result.stdout
    assert "06-request.md" not in result.stdout
    assert [path.name for path in sorted(workdir.iterdir())] == [
        "01-redacted.md",
        "02-signals.md",
        "03-approved.md",
        "04-packet.md",
        "05-diagnostics.md",
    ]
    packet = (workdir / "04-packet.md").read_text(encoding="utf-8")
    diagnostics = (workdir / "05-diagnostics.md").read_text(encoding="utf-8")
    assert "[REDACTED]" in packet
    assert "overall: fail" in diagnostics
    assert "| no redaction marker leaked | FAIL | redaction marker found |" in diagnostics
    assert not (workdir / "06-request.md").exists()


def test_cli_route_requires_explicit_approval_before_writing_artifacts(tmp_path: Path):
    note = tmp_path / "note.md"
    workdir = tmp_path / "route"
    note.write_text("Goal: build the route command.\n", encoding="utf-8")
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "route",
            str(note),
            "--source",
            "unit-route-note",
            "--agent",
            "docs-agent",
            "--task",
            "draft route command docs",
            "--workdir",
            str(workdir),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 2
    assert "--approve-all" in result.stderr
    assert "--select" in result.stderr
    assert "--reject" in result.stderr
    assert not workdir.exists()


def test_cli_route_select_writes_subset_packet(tmp_path: Path):
    note = tmp_path / "note.md"
    workdir = tmp_path / "route"
    note.write_text(
        "\n".join(
            [
                "Goal: keep selected route context.",
                "Goal: drop unselected route context.",
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "route",
            str(note),
            "--source",
            "unit-route-note",
            "--agent",
            "qa-agent",
            "--task",
            "verify selected route context",
            "--workdir",
            str(workdir),
            "--select",
            "3",
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    approved = (workdir / "03-approved.md").read_text(encoding="utf-8")
    packet = (workdir / "04-packet.md").read_text(encoding="utf-8")
    assert result.returncode == 0
    assert "approval: select" in approved
    assert "Selected indexes: 3" in approved
    assert "- Goal: keep selected route context." in packet
    assert "- Goal: drop unselected route context." not in packet


def test_cli_help_lists_diagnose_not_legacy_aliases():
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "--help",
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0
    assert "{redact,extract,approve,packet,stats,diagnose,doctor,request,writeback,route,run-sample}" in result.stdout
    assert "diagnose" in result.stdout
    assert "doctor" in result.stdout
    assert "Print a safe context packet size and shape summary." in result.stdout
    assert "Validate a context packet and write diagnostics." in result.stdout
    assert "Validate a generated PCR workdir." in result.stdout
    assert "{redact,extract,approve,packet,inspect,request,writeback,run-sample}" not in result.stdout
    assert "{redact,extract,approve,packet,diagnostics,request,writeback,run-sample}" not in result.stdout
    assert "diagnose          " in result.stdout
    assert "stats             " in result.stdout
    assert "doctor           " in result.stdout
    assert "inspect           " not in result.stdout
    assert "diagnostics        " not in result.stdout


def test_package_module_help_matches_cli_entrypoint():
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router",
            "--help",
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0
    assert "usage: pcr" in result.stdout
    assert "{redact,extract,approve,packet,stats,diagnose,doctor,request,writeback,route,run-sample}" in result.stdout
    assert "Personal context, routed safely." in result.stdout


def test_package_module_version_matches_cli_entrypoint():
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router",
            "--version",
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0
    assert result.stdout == f"pcr {__version__}\n"
    assert result.stderr == ""
