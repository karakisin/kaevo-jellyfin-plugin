"""Small command surface; mutating commands fail closed until preflight permits them."""

from __future__ import annotations

import argparse

from .errors import FixtureSafetyError
from .preflight import run_preflight
from .runner import create_fixture_b


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scripts.household_join_live")
    parser.add_argument("command", choices=("preflight", "create-fixture-a", "create-fixture-b", "watch-transactions", "safe-status", "cleanup", "verify-absence"))
    parser.add_argument("--fixture")
    parser.add_argument("--acknowledge-live-development-writes", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        import boto3

        result = run_preflight(session_factory=boto3.Session)
    except FixtureSafetyError as error:
        print(f"PREFLIGHT_FAILED code={error.code}")
        return 2
    print(result["event"])
    if arguments.command == "create-fixture-b":
        if not arguments.acknowledge_live_development_writes:
            print("REFUSED code=LIVE_DEVELOPMENT_WRITE_ACKNOWLEDGEMENT_REQUIRED")
            return 2
        result = create_fixture_b(session_factory=boto3.Session)
        print(f"{result['event']} marker={result['marker']} manifest={result['manifest_path']}")
        return 0
    if arguments.command != "preflight":
        # Creation and all follow-up commands deliberately cannot bypass the
        # transaction lookup invariant established by the same process.
        print("REFUSED code=RUNNER_NOT_ENABLED_AFTER_PREFLIGHT")
        return 2
    return 0
