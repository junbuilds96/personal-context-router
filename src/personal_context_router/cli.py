"""Command line interface for Personal Context Router."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import (
    ApprovalRequired,
    DiagnosticResult,
    DoctorResult,
    InvalidPipelineInput,
    RouteResult,
    approve_signals,
    create_packet,
    create_request,
    create_writeback,
    diagnose_packet,
    doctor_workdir,
    extract_signals,
    redact_file,
    run_route,
    run_sample,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcr",
        description="Personal context, routed safely.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subcommands = parser.add_subparsers(
        dest="command",
        metavar="{redact,extract,approve,packet,diagnose,doctor,request,writeback,route,run-sample}",
        required=True,
    )

    redact = subcommands.add_parser("redact", help="Redact obvious sensitive values from an input note.")
    redact.add_argument("input", metavar="INPUT")
    redact.add_argument("--out", required=True, metavar="OUTPUT")
    redact.set_defaults(func=_cmd_redact)

    extract = subcommands.add_parser("extract", help="Extract deterministic context signals from redacted input.")
    extract.add_argument("redacted_input", metavar="REDACTED_INPUT")
    extract.add_argument("--source", required=True, metavar="SOURCE")
    extract.add_argument("--out", required=True, metavar="SIGNALS_OUTPUT")
    extract.set_defaults(func=_cmd_extract)

    approve = subcommands.add_parser("approve", help="Approve extracted signals for packet generation.")
    approve.add_argument("signals_input", metavar="SIGNALS_INPUT")
    approval = approve.add_mutually_exclusive_group()
    approval.add_argument("--approve-all", action="store_true", help="Approve all selectable signal bullets.")
    approval.add_argument("--select", metavar="INDEXES", help="Approve only comma-separated signal indexes.")
    approval.add_argument("--reject", metavar="INDEXES", help="Approve all signal indexes except these.")
    approve.add_argument("--out", required=True, metavar="APPROVED_OUTPUT")
    approve.set_defaults(func=_cmd_approve)

    packet = subcommands.add_parser("packet", help="Build a task-scoped context packet from approved signals.")
    packet.add_argument("approved_input", metavar="APPROVED_INPUT")
    packet.add_argument("--agent", required=True, metavar="AGENT")
    packet.add_argument("--task", required=True, metavar="TASK")
    packet.add_argument("--out", required=True, metavar="PACKET_OUTPUT")
    packet.add_argument("--json-out", metavar="JSON_OUTPUT")
    packet.set_defaults(func=_cmd_packet)

    diagnose = subcommands.add_parser("diagnose", help="Validate a context packet and write diagnostics.")
    _add_diagnose_arguments(diagnose)

    inspect = subcommands.add_parser("inspect", help=argparse.SUPPRESS)
    _add_diagnose_arguments(inspect)
    _hide_subcommand(subcommands, "inspect")

    diagnostics = subcommands.add_parser("diagnostics", help=argparse.SUPPRESS)
    _add_diagnose_arguments(diagnostics)
    _hide_subcommand(subcommands, "diagnostics")

    doctor = subcommands.add_parser("doctor", help="Validate a generated PCR workdir.")
    doctor.add_argument("workdir", metavar="WORKDIR")
    doctor.add_argument("--out", metavar="REPORT")
    doctor.add_argument("--json-out", metavar="JSON")
    doctor.set_defaults(func=_cmd_doctor)

    request = subcommands.add_parser("request", help="Create an auditable context request from a packet.")
    request.add_argument("packet_input", metavar="PACKET_INPUT")
    request.add_argument("--out", required=True, metavar="REQUEST_OUTPUT")
    request.set_defaults(func=_cmd_request)

    writeback = subcommands.add_parser("writeback", help="Record whether a request had sufficient context.")
    writeback.add_argument("request_input", metavar="REQUEST_INPUT")
    writeback.add_argument("--out", required=True, metavar="WRITEBACK_OUTPUT")
    writeback.add_argument("--status", required=True, choices=["sufficient", "insufficient"])
    writeback.add_argument("--note", required=True, metavar="TEXT")
    writeback.add_argument("--decision-out", metavar="PATH")
    writeback.set_defaults(func=_cmd_writeback)

    route = subcommands.add_parser("route", help="Run the redacted one-command route pipeline.")
    route.add_argument("input", metavar="INPUT")
    route.add_argument("--source", required=True, metavar="SOURCE")
    route.add_argument("--agent", required=True, metavar="AGENT")
    route.add_argument("--task", required=True, metavar="TASK")
    route.add_argument("--workdir", required=True, metavar="DIR")
    route_approval = route.add_mutually_exclusive_group()
    route_approval.add_argument("--approve-all", action="store_true", help="Approve all selectable signal bullets.")
    route_approval.add_argument("--select", metavar="INDEXES", help="Approve only comma-separated signal indexes.")
    route_approval.add_argument("--reject", metavar="INDEXES", help="Approve all signal indexes except these.")
    route.add_argument("--json-out", metavar="JSON_OUTPUT")
    route.add_argument("--diagnostics-json-out", metavar="JSON_OUTPUT")
    route.set_defaults(func=_cmd_route)

    sample = subcommands.add_parser("run-sample", help="Run the complete synthetic demo workflow.")
    sample.add_argument("--workdir", required=True, metavar="DIR")
    sample.set_defaults(func=_cmd_run_sample)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        artifact = args.func(args)
    except (ApprovalRequired, InvalidPipelineInput, ValueError) as exc:
        parser.exit(2, f"pcr: error: {exc}\n")

    if isinstance(artifact, list):
        print("Wrote demo artifacts:")
        for item in artifact:
            print(f"- {item.path}")
    elif isinstance(artifact, RouteResult):
        print("Wrote route artifacts:")
        for item in artifact.artifacts:
            print(f"- {item.path}")
        print(f"Diagnostics: {'pass' if artifact.diagnostics.passed else 'fail'}")
        return 0 if artifact.diagnostics.passed else 1
    elif isinstance(artifact, DiagnosticResult):
        print(f"Wrote {artifact.artifact.path}")
        print(f"Diagnostics: {'pass' if artifact.passed else 'fail'}")
        return 0 if artifact.passed else 1
    elif isinstance(artifact, DoctorResult):
        if artifact.artifact is None:
            print(artifact.report_text, end="")
        else:
            print(f"Wrote {artifact.artifact.path}")
            print(f"Doctor: {'pass' if artifact.passed else 'fail'}")
        return 0 if artifact.passed else 1
    else:
        print(f"Wrote {artifact.path}")
    return 0


def _cmd_redact(args: argparse.Namespace):
    return redact_file(args.input, args.out)


def _cmd_extract(args: argparse.Namespace):
    return extract_signals(args.redacted_input, args.source, args.out)


def _cmd_approve(args: argparse.Namespace):
    return approve_signals(
        args.signals_input,
        args.out,
        approve_all=args.approve_all,
        select=args.select,
        reject=args.reject,
    )


def _cmd_packet(args: argparse.Namespace):
    return create_packet(
        args.approved_input,
        args.agent,
        args.task,
        args.out,
        args.json_out,
    )


def _hide_subcommand(subcommands: argparse._SubParsersAction, name: str) -> None:
    subcommands._choices_actions = [
        action for action in subcommands._choices_actions if action.dest != name
    ]


def _add_diagnose_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("packet_input", metavar="PACKET_INPUT")
    parser.add_argument("--out", required=True, metavar="DIAGNOSTICS_OUTPUT")
    parser.add_argument("--json-out", metavar="JSON_OUTPUT")
    parser.set_defaults(func=_cmd_diagnose)


def _cmd_diagnose(args: argparse.Namespace):
    return diagnose_packet(args.packet_input, args.out, args.json_out)


def _cmd_doctor(args: argparse.Namespace):
    return doctor_workdir(args.workdir, args.out, args.json_out)


def _cmd_request(args: argparse.Namespace):
    return create_request(args.packet_input, args.out)


def _cmd_writeback(args: argparse.Namespace):
    return create_writeback(
        args.request_input,
        args.out,
        status=args.status,
        note=args.note,
        decision_out=args.decision_out,
    )


def _cmd_route(args: argparse.Namespace):
    return run_route(
        args.input,
        source=args.source,
        agent=args.agent,
        task=args.task,
        workdir=args.workdir,
        approve_all=args.approve_all,
        select=args.select,
        reject=args.reject,
        json_output_path=args.json_out,
        diagnostics_json_output_path=args.diagnostics_json_out,
    )


def _cmd_run_sample(args: argparse.Namespace):
    return run_sample(args.workdir)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
