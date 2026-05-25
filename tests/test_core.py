from pathlib import Path
import os
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


def test_cli_inspect_fails_nonzero_and_writes_report(tmp_path: Path):
    packet = tmp_path / "packet.md"
    report = tmp_path / "diagnostics.md"
    packet.write_text("---\ntype: context_packet\n---\n\n# Packet\n", encoding="utf-8")
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "personal_context_router.cli",
            "inspect",
            str(packet),
            "--out",
            str(report),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 1
    assert "Diagnostics: fail" in result.stdout
    assert report.exists()
    assert "overall: fail" in report.read_text(encoding="utf-8")


def test_cli_help_lists_inspect_not_legacy_aliases():
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
    assert "{redact,extract,approve,packet,inspect,request,writeback,run-sample}" in result.stdout
    assert "inspect" in result.stdout
    assert "Validate a context packet and write diagnostics." in result.stdout
    assert "{redact,extract,approve,packet,diagnose,request,writeback,run-sample}" not in result.stdout
    assert "{redact,extract,approve,packet,diagnostics,request,writeback,run-sample}" not in result.stdout
    assert "diagnose          " not in result.stdout
    assert "diagnostics        " not in result.stdout
