import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from personal_context_router.core import (
    ApprovalRequired,
    REDACTION_MARKER,
    approve_signals,
    create_packet,
    create_request,
    create_writeback,
    diagnose_packet,
    extract_signals,
    redact_content,
    redact_file,
    run_sample,
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
    assert data["counts"] == {"total": 13, "passed": 13, "failed": 0}
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
    assert "| no [REDACTED] marker leaked | FAIL | [REDACTED] marker found |" in diagnostics.artifact.text
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
    assert data["counts"]["total"] == 13
    assert data["counts"]["passed"] < 13
    assert data["counts"]["failed"] > 0
    assert {
        "name": "artifact type is context_packet",
        "result": "fail",
        "detail": "expected type=context_packet; found context_signals",
    } in data["checks"]
    assert {
        "name": "no [REDACTED] marker leaked",
        "result": "fail",
        "detail": "[REDACTED] marker found",
    } in data["checks"]


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
        "05-request.md",
        "06-writeback.md",
    ]
    assert (tmp_path / "07-decision.md").exists()
    packet = (tmp_path / "04-packet.md").read_text(encoding="utf-8")
    assert "type: context_packet" in packet
    assert "[REDACTED]" not in packet
    assert "- Safety constraints:" not in packet
    assert "- Agent needs:" not in packet
    for name in ("02-signals.md", "03-approved.md", "04-packet.md"):
        generated = (tmp_path / name).read_text(encoding="utf-8")
        assert "\n        #" not in generated
        assert "\n        -" not in generated


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
    assert "{redact,extract,approve,packet,diagnose,request,writeback,run-sample}" in result.stdout
    assert "diagnose" in result.stdout
    assert "Validate a context packet and write diagnostics." in result.stdout
    assert "{redact,extract,approve,packet,inspect,request,writeback,run-sample}" not in result.stdout
    assert "{redact,extract,approve,packet,diagnostics,request,writeback,run-sample}" not in result.stdout
    assert "diagnose          " in result.stdout
    assert "inspect           " not in result.stdout
    assert "diagnostics        " not in result.stdout
