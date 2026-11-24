#!/usr/bin/env python3
"""
Enterprise Platform Mesh - Unified Control Plane, Drift Detector & Audit Ledger.

Evaluates deployment manifests against EU/Nordic residency policies, payload bounds,
resource quotas, disaster-recovery readiness, and cryptographic audit chaining.
Includes a deterministic self-verification suite (--self-test) for CI/CD gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_REGIONS = frozenset({"eu-north-1", "europe-north1"})
ALLOWED_ENVIRONMENTS = frozenset({"staging", "production"})
ALLOWED_TIERS = frozenset({"standard", "restricted", "regulated"})
MAX_PAYLOAD_BYTES = 1024 * 1024  # 1 MiB strict upper bound
MAX_REPLICAS = 12
MIN_PRODUCTION_REPLICAS = 2

EXIT_PASS = 0
EXIT_POLICY_VIOLATION = 1
EXIT_SYSTEM_ERROR = 2


@dataclass(frozen=True)
class GateEvaluation:
    gate_id: str
    layer: str
    severity: str
    passed: bool
    message: str


@dataclass(frozen=True)
class DriftFinding:
    field_name: str
    baseline_value: Any
    observed_value: Any
    status: str


@dataclass(frozen=True)
class ControlPlaneReport:
    schema_version: str
    evaluated_at_utc: str
    service_name: str
    environment: str
    region: str
    compliance_tier: str
    payload_bytes: int
    replicas: int
    exit_code: int
    verdict: str
    gates: list[dict[str, Any]]
    drift_findings: list[dict[str, Any]]
    previous_chain_sha256: str
    record_sha256: str


@dataclass
class DeploymentSpec:
    service_name: str
    environment: str
    region: str
    compliance_tier: str
    payload_bytes: int
    replicas: int
    encryption_at_rest: bool = True
    network_egress_locked: bool = True
    labels: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> DeploymentSpec:
        return cls(
            service_name=str(raw.get("service_name", "")).strip(),
            environment=str(raw.get("environment", "")).strip().lower(),
            region=str(raw.get("region", "")).strip().lower(),
            compliance_tier=str(raw.get("compliance_tier", "regulated")).strip().lower(),
            payload_bytes=int(raw.get("payload_bytes", -1)),
            replicas=int(raw.get("replicas", 0)),
            encryption_at_rest=bool(raw.get("encryption_at_rest", False)),
            network_egress_locked=bool(raw.get("network_egress_locked", False)),
            labels=dict(raw.get("labels", {})) if isinstance(raw.get("labels"), dict) else {},
        )


def compute_canonical_sha256(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class DisasterRecoveryVerifier:
    """Validates backup directory existence, non-empty snapshot artifacts, and readability."""

    def __init__(self, backup_dir: Path) -> None:
        self.backup_dir = backup_dir

    def verify(self) -> GateEvaluation:
        if not self.backup_dir.exists() or not self.backup_dir.is_dir():
            return GateEvaluation(
                gate_id="GATE-DR-01",
                layer="disaster-recovery",
                severity="CRITICAL",
                passed=False,
                message=f"DR backup directory '{self.backup_dir}' is missing or invalid.",
            )

        try:
            artifacts = [
                entry
                for entry in self.backup_dir.iterdir()
                if entry.is_file() and os.access(entry, os.R_OK)
            ]
        except OSError as exc:
            return GateEvaluation(
                gate_id="GATE-DR-01",
                layer="disaster-recovery",
                severity="CRITICAL",
                passed=False,
                message=f"Unable to inspect DR directory '{self.backup_dir}': {exc}",
            )

        if not artifacts:
            return GateEvaluation(
                gate_id="GATE-DR-01",
                layer="disaster-recovery",
                severity="CRITICAL",
                passed=False,
                message=f"DR directory '{self.backup_dir}' has zero readable snapshot artifacts.",
            )

        return GateEvaluation(
            gate_id="GATE-DR-01",
            layer="disaster-recovery",
            severity="INFO",
            passed=True,
            message=f"Verified {len(artifacts)} readable DR artifact(s) in '{self.backup_dir}'.",
        )


class DriftEngine:
    """Compares live deployment specifications against an approved baseline."""

    TRACKED_FIELDS = (
        "environment",
        "region",
        "compliance_tier",
        "replicas",
        "encryption_at_rest",
        "network_egress_locked",
    )

    def compare(self, spec: DeploymentSpec, baseline: dict[str, Any] | None) -> list[DriftFinding]:
        if not baseline:
            return []
        findings: list[DriftFinding] = []
        spec_map = asdict(spec)
        for field_name in self.TRACKED_FIELDS:
            if field_name not in baseline:
                continue
            expected = baseline[field_name]
            observed = spec_map.get(field_name)
            if expected != observed:
                findings.append(
                    DriftFinding(
                        field_name=field_name,
                        baseline_value=expected,
                        observed_value=observed,
                        status="DRIFT_DETECTED",
                    )
                )
        return findings


class PolicyControlPlane:
    """Core multi-gate enforcement engine for Nordic/EU platform deployments."""

    def __init__(self, backup_dir: Path, strict_drift: bool = True) -> None:
        self.dr_verifier = DisasterRecoveryVerifier(backup_dir)
        self.drift_engine = DriftEngine()
        self.strict_drift = strict_drift

    def evaluate(
        self,
        spec: DeploymentSpec,
        baseline: dict[str, Any] | None = None,
        previous_chain_sha256: str = "GENESIS",
    ) -> tuple[int, ControlPlaneReport]:
        gates: list[GateEvaluation] = []

        # 1. Service Identity & Metadata Gate
        identity_ok = bool(spec.service_name) and len(spec.service_name) <= 64
        gates.append(
            GateEvaluation(
                gate_id="GATE-ID-01",
                layer="identity-governance",
                severity="HIGH",
                passed=identity_ok,
                message="Service identity verified."
                if identity_ok
                else "Service name must be 1..64 non-empty characters.",
            )
        )

        # 2. Environment & Compliance Tier Gate
        env_ok = spec.environment in ALLOWED_ENVIRONMENTS and spec.compliance_tier in ALLOWED_TIERS
        gates.append(
            GateEvaluation(
                gate_id="GATE-ENV-02",
                layer="environment-tier",
                severity="HIGH",
                passed=env_ok,
                message=f"Environment '{spec.environment}' and tier '{spec.compliance_tier}' approved."
                if env_ok
                else f"Invalid environment/tier: ({spec.environment}, {spec.compliance_tier}).",
            )
        )

        # 3. EU/Nordic Data Residency Gate
        region_ok = spec.region in ALLOWED_REGIONS
        gates.append(
            GateEvaluation(
                gate_id="GATE-RES-03",
                layer="eu-nordic-residency",
                severity="CRITICAL",
                passed=region_ok,
                message=f"Region '{spec.region}' satisfies EU/Nordic residency policy."
                if region_ok
                else f"Region '{spec.region}' blocked; allowed regions: {sorted(ALLOWED_REGIONS)}.",
            )
        )

        # 4. Payload & Blast-Radius Capacity Gate
        payload_ok = 0 < spec.payload_bytes <= MAX_PAYLOAD_BYTES
        replica_min = MIN_PRODUCTION_REPLICAS if spec.environment == "production" else 1
        replicas_ok = replica_min <= spec.replicas <= MAX_REPLICAS
        capacity_ok = payload_ok and replicas_ok
        gates.append(
            GateEvaluation(
                gate_id="GATE-CAP-04",
                layer="capacity-blast-radius",
                severity="CRITICAL",
                passed=capacity_ok,
                message=(
                    f"Payload {spec.payload_bytes}B (<=1 MiB) and replicas={spec.replicas} within bounds."
                    if capacity_ok
                    else f"Capacity bound failed: payload={spec.payload_bytes}B, replicas={spec.replicas}."
                ),
            )
        )

        # 5. Zero-Trust Security Posture Gate
        security_ok = spec.encryption_at_rest and spec.network_egress_locked
        gates.append(
            GateEvaluation(
                gate_id="GATE-SEC-05",
                layer="zero-trust-posture",
                severity="CRITICAL",
                passed=security_ok,
                message="Encryption-at-rest and egress lock active."
                if security_ok
                else "Security posture requires both encryption_at_rest=True and network_egress_locked=True.",
            )
        )

        # 6. Drift Gate
        drift_findings = self.drift_engine.compare(spec, baseline)
        drift_ok = (len(drift_findings) == 0) or (not self.strict_drift)
        gates.append(
            GateEvaluation(
                gate_id="GATE-DFT-06",
                layer="configuration-drift",
                severity="HIGH",
                passed=drift_ok,
                message="Zero configuration drift against baseline."
                if len(drift_findings) == 0
                else f"Detected {len(drift_findings)} configuration drift item(s).",
            )
        )

        # 7. Disaster Recovery Snapshot Gate
        dr_gate = self.dr_verifier.verify()
        gates.append(dr_gate)

        policy_gates_ok = all(
            g.passed for g in gates if g.gate_id != "GATE-DR-01"
        )

        if not dr_gate.passed:
            exit_code = EXIT_SYSTEM_ERROR
            verdict = "BLOCK_SYSTEM_ERROR"
        elif not policy_gates_ok:
            exit_code = EXIT_POLICY_VIOLATION
            verdict = "BLOCK_POLICY_VIOLATION"
        else:
            exit_code = EXIT_PASS
            verdict = "ALLOW_RELEASE"

        unsigned_report = {
            "schema_version": "2.0.0",
            "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
            "service_name": spec.service_name or "unknown",
            "environment": spec.environment,
            "region": spec.region,
            "compliance_tier": spec.compliance_tier,
            "payload_bytes": spec.payload_bytes,
            "replicas": spec.replicas,
            "exit_code": exit_code,
            "verdict": verdict,
            "gates": [asdict(g) for g in gates],
            "drift_findings": [asdict(d) for d in drift_findings],
            "previous_chain_sha256": previous_chain_sha256,
        }
        record_hash = compute_canonical_sha256(unsigned_report)
        report = ControlPlaneReport(**unsigned_report, record_sha256=record_hash)
        return exit_code, report


def run_self_test() -> int:
    """Runs deterministic verification tests covering ALLOW, POLICY_VIOLATION, and SYSTEM_ERROR."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        valid_dr = Path(tmp_dir) / "dr-backup"
        valid_dr.mkdir(parents=True, exist_ok=True)
        (valid_dr / "snapshot.meta").write_text("ok\n", encoding="utf-8")

        engine = PolicyControlPlane(backup_dir=valid_dr, strict_drift=True)

        # Case 1: Valid EU/Nordic production spec -> EXIT_PASS (0)
        good_spec = DeploymentSpec(
            service_name="platform-mesh-core",
            environment="production",
            region="eu-north-1",
            compliance_tier="regulated",
            payload_bytes=10240,
            replicas=3,
            encryption_at_rest=True,
            network_egress_locked=True,
        )
        code_ok, report_ok = engine.evaluate(good_spec, baseline={"region": "eu-north-1", "replicas": 3})
        assert code_ok == EXIT_PASS, f"Expected 0, got {code_ok}"

        # Case 2: Non-EU region + >1 MiB payload -> EXIT_POLICY_VIOLATION (1)
        bad_spec = DeploymentSpec(
            service_name="platform-mesh-core",
            environment="production",
            region="us-east-1",
            compliance_tier="regulated",
            payload_bytes=MAX_PAYLOAD_BYTES + 512,
            replicas=3,
            encryption_at_rest=True,
            network_egress_locked=True,
        )
        code_viol, _ = engine.evaluate(bad_spec, previous_chain_sha256=report_ok.record_sha256)
        assert code_viol == EXIT_POLICY_VIOLATION, f"Expected 1, got {code_viol}"

        # Case 3: Missing DR directory -> EXIT_SYSTEM_ERROR (2)
        broken_engine = PolicyControlPlane(backup_dir=Path(tmp_dir) / "missing-dr")
        code_err, _ = broken_engine.evaluate(good_spec)
        assert code_err == EXIT_SYSTEM_ERROR, f"Expected 2, got {code_err}"

    summary = {
        "self_test": "PASSED",
        "verified_exit_codes": [EXIT_PASS, EXIT_POLICY_VIOLATION, EXIT_SYSTEM_ERROR],
        "verified_gates": 7,
    }
    print(json.dumps(summary, indent=2))
    return EXIT_PASS


def load_spec_from_env() -> DeploymentSpec:
    return DeploymentSpec.from_dict(
        {
            "service_name": os.getenv("SERVICE_NAME", "platform-mesh-core"),
            "environment": os.getenv("DEPLOY_ENV", "production"),
            "region": os.getenv("GUARDRAIL_REGION", "eu-north-1"),
            "compliance_tier": os.getenv("COMPLIANCE_TIER", "regulated"),
            "payload_bytes": int(os.getenv("PAYLOAD_BYTES", "10240")),
            "replicas": int(os.getenv("REPLICAS", "3")),
            "encryption_at_rest": os.getenv("ENCRYPTION_AT_REST", "true").lower() == "true",
            "network_egress_locked": os.getenv("NETWORK_EGRESS_LOCKED", "true").lower() == "true",
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Enterprise Mesh Guardrail Control Plane")
    parser.add_argument("--self-test", action="store_true", help="Run built-in verification suite")
    parser.add_argument("--manifest", type=str, default="", help="Optional JSON manifest path")
    parser.add_argument("--baseline", type=str, default="", help="Optional JSON baseline path")
    parser.add_argument("--audit-out", type=str, default="", help="Optional output audit JSON path")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    backup_dir = Path(os.getenv("DR_BACKUP_DIR", "dr-backup"))
    try:
        if args.manifest:
            raw = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            spec = DeploymentSpec.from_dict(raw)
        else:
            spec = load_spec_from_env()

        baseline = (
            json.loads(Path(args.baseline).read_text(encoding="utf-8")) if args.baseline else None
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        err = {"exit_code": EXIT_SYSTEM_ERROR, "verdict": "BLOCK_SYSTEM_ERROR", "error": str(exc)}
        print(json.dumps(err, indent=2), file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    engine = PolicyControlPlane(backup_dir=backup_dir, strict_drift=True)
    code, report = engine.evaluate(spec=spec, baseline=baseline)
    rendered = json.dumps(asdict(report), indent=2)

    if args.audit_out:
        Path(args.audit_out).write_text(rendered + "\n", encoding="utf-8")

    print(rendered, file=sys.stdout if code == EXIT_PASS else sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
          
