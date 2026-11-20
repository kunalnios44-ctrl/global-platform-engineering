import json
import sys
from typing import Any, Dict, List


def validate_dr_report(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("DR report must be a JSON object")

    required_fields = [
        "backup_id",
        "region",
        "status",
        "age_minutes",
        "max_rpo_minutes",
        "size_bytes",
        "sha256_expected",
        "sha256_actual",
        "restore_tested",
    ]
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")

    if not isinstance(data["backup_id"], str) or not data["backup_id"].strip():
        raise ValueError("backup_id must be a non-empty string")
    if not isinstance(data["region"], str) or not data["region"].strip():
        raise ValueError("region must be a non-empty string")
    if not isinstance(data["status"], str) or not data["status"].strip():
        raise ValueError("status must be a non-empty string")

    for num_field in ["age_minutes", "max_rpo_minutes", "size_bytes"]:
        val = data[num_field]
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise ValueError(f"{num_field} must be a non-negative integer")

    if not isinstance(data["sha256_expected"], str) or not isinstance(data["sha256_actual"], str):
        raise ValueError("SHA-256 fields must be strings")
    if not isinstance(data["restore_tested"], bool):
        raise ValueError("restore_tested must be strictly true/false")

    return data


def verify_dr_readiness(report: Dict[str, Any]) -> List[str]:
    issues: List[str] = []

    if report["status"].lower() != "ready":
        issues.append(f"Backup status is '{report['status']}', expected 'ready'")

    if report["size_bytes"] <= 0:
        issues.append("Backup size is zero; artifact/snapshot may be empty")

    if report["age_minutes"] > report["max_rpo_minutes"]:
        issues.append(
            f"RPO breached: backup age ({report['age_minutes']}m) > max allowed ({report['max_rpo_minutes']}m)"
        )

    expected_hash = report["sha256_expected"].strip().lower()
    actual_hash = report["sha256_actual"].strip().lower()
    if not expected_hash or expected_hash != actual_hash:
        issues.append("SHA-256 checksum mismatch between expected and actual backup")

    if not report["restore_tested"]:
        issues.append("Restore verification test has not passed")

    return issues


def main() -> int:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            raise ValueError("Empty input on stdin")
        if len(raw.encode("utf-8")) > 1048576:
            raise ValueError("Input exceeds 1 MiB limit")
        parsed = json.loads(raw)
        report = validate_dr_report(parsed)
    except Exception as exc:
        print(f"[DR_RUNTIME_ERROR] {exc}", file=sys.stderr)
        return 2

    issues = verify_dr_readiness(report)
    if issues:
        for item in issues:
            print(f"[DR_VIOLATION] {item}", file=sys.stderr)
        return 1

    print(f"[DR_READY] Verified backup '{report['backup_id']}' in {report['region']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
          
