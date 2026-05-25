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
    assert "type: context_packet" in (tmp_path / "04-packet.md").read_text(encoding="utf-8")


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
