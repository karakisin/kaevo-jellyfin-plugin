#!/usr/bin/env python3
"""Derive publishable V3 verification material without exposing the seed.

This is a post-deployment operator tool.  It reads the retained dev secret
directly from Secrets Manager, keeps the seed only in process memory, and emits
only the safe ``kid`` and Ed25519 public key needed by the iOS and Plugin
validation candidates.  It never accepts a seed through arguments, files, or
standard input, and never prints one.
"""

from __future__ import annotations

import argparse
import base64
import json
import re

import boto3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


SEED_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-id", required=True, help="Pairing V3 signing secret ARN or name")
    parser.add_argument("--kid", required=True, help="Pinned public verification key identifier")
    parser.add_argument("--profile", required=True, help="AWS profile with direct access to this exact secret")
    parser.add_argument("--region", required=True, help="AWS region containing the secret")
    args = parser.parse_args()

    response = boto3.Session(profile_name=args.profile, region_name=args.region).client("secretsmanager").get_secret_value(
        SecretId=args.secret_id
    )
    encoded_seed = response.get("SecretString")
    if not isinstance(encoded_seed, str) or not SEED_PATTERN.fullmatch(encoded_seed):
        raise SystemExit("Pairing V3 signing secret is malformed")
    try:
        seed = base64.urlsafe_b64decode(encoded_seed + "=")
    except ValueError as error:
        raise SystemExit("Pairing V3 signing secret is malformed") from error
    if len(seed) != 32:
        raise SystemExit("Pairing V3 signing secret is malformed")

    public_key = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print(json.dumps({"kid": args.kid, "publicKey": base64url(public_key)}, separators=(",", ":")))


if __name__ == "__main__":
    main()
