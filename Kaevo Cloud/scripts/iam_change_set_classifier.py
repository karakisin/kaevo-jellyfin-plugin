"""Fail-closed classification for an IAM change set with intrinsic dependencies."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping


DIRECT = "DIRECT_STATIC_CHANGE"
DYNAMIC = "INDIRECT_DYNAMIC_REFERENCE"
PARAMETER = "PARAMETER_STATIC_CHANGE"
ARTIFACT = "ARTIFACT_LOCATION_CHANGE"
TRANSFORM = "TRANSFORM_OUTPUT_CHANGE"
NONE = "NO_MODIFICATION_DETAIL"
UNEXPLAINED = "UNEXPLAINED_REAL_CHANGE"

_DYNAMIC_SOURCES = {"ResourceReference", "ResourceAttribute"}
_ARTIFACT_NAMES = {"Code", "CodeUri", "DefinitionUri", "BodyS3Location", "S3Bucket", "S3Key", "S3ObjectVersion"}
_SECRET_VALUE = re.compile(r"(?i)(secret|token|password|authorization[_ -]?code|access[_ -]?key)")


def safe_fingerprint(value: object) -> str:
    """Represent evidence without returning its potentially sensitive value."""
    canonical = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


def redact_value(value: object) -> str:
    rendered = json.dumps(value, sort_keys=True, default=str)
    return "[redacted]" if _SECRET_VALUE.search(rendered) else safe_fingerprint(value)


def flatten_change_set_pages(pages: Iterable[Mapping]) -> list[Mapping]:
    """Flatten paginated DescribeChangeSet pages and reject duplicate changes."""
    flattened: list[Mapping] = []
    seen: set[tuple[str, str]] = set()
    tokens: set[str] = set()
    for page in pages:
        if not isinstance(page, Mapping):
            raise ValueError("change_set_page_invalid")
        token = page.get("NextToken")
        if token is not None:
            if not isinstance(token, str) or not token or token in tokens:
                raise ValueError("change_set_pagination_invalid")
            tokens.add(token)
        for change in page.get("Changes") or []:
            resource = (change or {}).get("ResourceChange") or {}
            key = (str(resource.get("LogicalResourceId") or ""), str(resource.get("Action") or ""))
            if not all(key) or key in seen:
                raise ValueError("change_set_change_duplicate_or_invalid")
            seen.add(key)
            flattened.append(change)
    return flattened


def classify_detail(detail: Mapping, *, template_proves_direct_delta: bool = False) -> str:
    target = detail.get("Target") or {}
    name = str(target.get("Name") or "")
    evaluation = detail.get("Evaluation")
    source = detail.get("ChangeSource")
    before, after = detail.get("BeforeValue"), detail.get("AfterValue")
    if evaluation == "Dynamic" and source in _DYNAMIC_SOURCES:
        return DYNAMIC if detail.get("CausingEntity") else UNEXPLAINED
    if evaluation == "Static" and source == "DirectModification":
        return DIRECT if template_proves_direct_delta or before != after else UNEXPLAINED
    if evaluation == "Static" and source == "ParameterReference":
        return PARAMETER
    if name in _ARTIFACT_NAMES or "S3" in name and "Body" in name:
        return ARTIFACT
    if source in {"NoModification", "NoChange"}:
        return NONE
    if evaluation == "Static" and source == "DirectModification" and before == after:
        return TRANSFORM
    return UNEXPLAINED


def classify_change_set(
    pages: Iterable[Mapping],
    *,
    direct_targets: set[tuple[str, str]],
    expected_causes: Mapping[tuple[str, str], set[str]],
) -> tuple[str, list[tuple[str, str, str]]]:
    """Return the only execution-safe class or a fail-closed alternative."""
    details: list[tuple[str, str, str]] = []
    for change in flatten_change_set_pages(pages):
        resource = change["ResourceChange"]
        logical = str(resource["LogicalResourceId"])
        for detail in resource.get("Details") or []:
            name = str((detail.get("Target") or {}).get("Name") or "")
            category = classify_detail(detail, template_proves_direct_delta=(logical, name) in direct_targets)
            details.append((logical, name, category))
            if category == DYNAMIC and detail.get("CausingEntity") not in expected_causes.get((logical, name), set()):
                return "DEPENDENCY_ATTRIBUTION_AMBIGUOUS", details
    direct = {(logical, name) for logical, name, category in details if category == DIRECT}
    if any(category in {UNEXPLAINED, PARAMETER, ARTIFACT, TRANSFORM} for _, _, category in details):
        return "REAL_MULTI_RESOURCE_CHANGE", details
    if direct != direct_targets:
        return "REAL_MULTI_RESOURCE_CHANGE", details
    if any(category not in {DIRECT, DYNAMIC, NONE} for _, _, category in details):
        return "REAL_MULTI_RESOURCE_CHANGE", details
    return "ONE_DIRECT_PLUS_DYNAMIC_NOOP_DEPENDENCIES", details
