from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import httpx

from app.config import settings

_SCAN_CACHE: dict[str, Any] = {
    "ts": 0.0,
    "result": None,
}


def get_risk_score_metadata(input_text: str) -> dict[str, Any]:
    text = str(input_text or "").strip().lower()
    if not text:
        return {
            "risk_id": "RISK-001",
            "risk_score": 0.0,
            "severity": "LOW",
        }

    high_impact_keywords = {
        "ignore previous instructions": 3.0,
        "reveal system prompt": 3.0,
        "api key": 2.5,
        "credential": 2.5,
        "secret": 2.0,
        "token": 2.0,
        "bypass": 2.0,
        "override": 2.0,
        "developer mode": 2.0,
        "act as admin": 2.0,
    }
    medium_impact_keywords = {
        "database": 1.2,
        "memory": 1.2,
        "internal policy": 1.2,
        "disable safeguards": 1.5,
        "system instructions": 1.5,
        "prompt injection": 1.5,
    }

    score = min(2.5, len(text) / 140.0)
    for key, weight in high_impact_keywords.items():
        if key in text:
            score += weight
    for key, weight in medium_impact_keywords.items():
        if key in text:
            score += weight

    score = max(0.0, min(10.0, round(score, 2)))
    if score >= 8.0:
        severity = "CRITICAL"
    elif score >= 6.0:
        severity = "HIGH"
    elif score >= 3.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_id": "RISK-001",
        "risk_score": score,
        "severity": severity,
    }


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "backend" / "requirements.txt").exists():
            return parent
        if (parent / "requirements.txt").exists():
            return parent
    return Path.cwd()


def _first_existing_path(candidates: list[Path]) -> Path | None:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _manifest_label(path: Path) -> str:
    parts = set(path.parts)
    if "backend" in parts:
        return "backend/requirements.txt"
    if "frontend" in parts:
        return "frontend/package-lock.json"
    return path.as_posix()


def _clean_python_name(name: str) -> str:
    return str(name or "").split("[", 1)[0].strip().lower()


def _parse_python_requirements(path: Path, manifest_label: str) -> tuple[list[dict[str, str]], list[str]]:
    deps: list[dict[str, str]] = []
    unpinned: list[str] = []
    if not path.exists():
        return deps, unpinned

    lines = path.read_text(encoding="utf-8").splitlines()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            unpinned.append(line)
            continue
        name, version = line.split("==", 1)
        clean_name = _clean_python_name(name)
        clean_version = str(version).split(";")[0].strip()
        if not clean_name or not clean_version:
            unpinned.append(line)
            continue
        deps.append(
            {
                "ecosystem": "PyPI",
                "name": clean_name,
                "version": clean_version,
                "manifest": manifest_label,
            }
        )
    return deps, unpinned


def _parse_npm_lock(path: Path, manifest_label: str) -> tuple[list[dict[str, str]], list[str]]:
    deps: list[dict[str, str]] = []
    unpinned: list[str] = []
    if not path.exists():
        return deps, unpinned

    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return deps, ["frontend/package-lock.json:parse_error"]

    packages = lock.get("packages", {}) if isinstance(lock, dict) else {}
    root = packages.get("", {}) if isinstance(packages, dict) else {}
    root_deps = set((root.get("dependencies") or {}).keys()) | set((root.get("devDependencies") or {}).keys())

    for name in sorted(root_deps):
        node = packages.get(f"node_modules/{name}", {}) if isinstance(packages, dict) else {}
        version = str(node.get("version") or "").strip()
        if not version:
            unpinned.append(name)
            continue
        deps.append(
            {
                "ecosystem": "npm",
                "name": str(name).strip(),
                "version": version,
                "manifest": manifest_label,
            }
        )
    return deps, unpinned


def _severity_from_osv(vuln: dict[str, Any]) -> str:
    db_sev = str((vuln.get("database_specific") or {}).get("severity") or "").strip().upper()
    if db_sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return db_sev

    for sev in vuln.get("severity") or []:
        value = str((sev or {}).get("score") or "")
        if "CVSS" in value.upper():
            # handle forms like CVSS:3.1/AV:N/... or embedded score text
            num_match = re.search(r"([0-9]+(?:\.[0-9]+)?)", value)
            if num_match:
                score = float(num_match.group(1))
                if score >= 9.0:
                    return "CRITICAL"
                if score >= 7.0:
                    return "HIGH"
                if score >= 4.0:
                    return "MEDIUM"
                return "LOW"

    blob = " ".join(
        [
            str(vuln.get("summary") or ""),
            str(vuln.get("details") or ""),
            str(vuln.get("id") or ""),
        ]
    ).lower()
    if "critical" in blob:
        return "CRITICAL"
    if "high" in blob:
        return "HIGH"
    if "medium" in blob:
        return "MEDIUM"
    if "low" in blob:
        return "LOW"
    return "HIGH"


def _query_osv_for_dep(dep: dict[str, str]) -> tuple[list[dict[str, Any]], str | None]:
    url = str(settings.supply_chain_scan_osv_url).strip() or "https://api.osv.dev/v1/query"
    payload = {
        "version": dep["version"],
        "package": {
            "name": dep["name"],
            "ecosystem": dep["ecosystem"],
        },
    }
    try:
        with httpx.Client(timeout=max(1, int(settings.supply_chain_scan_timeout_sec))) as client:
            resp = client.post(url, json=payload)
        if resp.status_code != 200:
            return [], f"osv_http_{resp.status_code}"
        data = resp.json() if resp.text else {}
    except Exception as exc:
        return [], str(exc)

    vulns = data.get("vulns") or []
    normalized: list[dict[str, Any]] = []
    for vuln in vulns:
        normalized.append(
            {
                "id": str(vuln.get("id") or "UNKNOWN"),
                "summary": str(vuln.get("summary") or ""),
                "details": str(vuln.get("details") or ""),
                "severity": _severity_from_osv(vuln),
                "references": [str(r.get("url")) for r in (vuln.get("references") or []) if r.get("url")],
                "package_name": dep["name"],
                "package_version": dep["version"],
                "ecosystem": dep["ecosystem"],
                "manifest": dep["manifest"],
            }
        )
    return normalized, None


def run_supply_chain_scan(force_refresh: bool = False) -> dict[str, Any]:
    now = time.time()
    ttl = max(30, int(settings.supply_chain_scan_cache_seconds))
    if not force_refresh and _SCAN_CACHE.get("result") and (now - float(_SCAN_CACHE.get("ts") or 0.0) < ttl):
        return _SCAN_CACHE["result"]

    root = _repo_root()
    python_manifest = _first_existing_path(
        [
            root / "backend" / "requirements.txt",
            root / "requirements.txt",
            Path.cwd() / "backend" / "requirements.txt",
            Path.cwd() / "requirements.txt",
            Path("/app/requirements.txt"),
        ]
    )
    npm_manifest = _first_existing_path(
        [
            root / "frontend" / "package-lock.json",
            Path.cwd() / "frontend" / "package-lock.json",
            Path("/app/frontend/package-lock.json"),
        ]
    )

    py_deps: list[dict[str, str]] = []
    py_unpinned: list[str] = []
    npm_deps: list[dict[str, str]] = []
    npm_unpinned: list[str] = []
    if python_manifest:
        py_deps, py_unpinned = _parse_python_requirements(python_manifest, _manifest_label(python_manifest))
    if npm_manifest:
        npm_deps, npm_unpinned = _parse_npm_lock(npm_manifest, _manifest_label(npm_manifest))
    deps = py_deps + npm_deps
    unpinned = py_unpinned + npm_unpinned

    max_packages = max(1, int(settings.supply_chain_scan_max_packages))
    deps = deps[:max_packages]
    vulnerabilities: list[dict[str, Any]] = []
    errors: list[str] = []

    if not settings.supply_chain_scan_enabled:
        result = {
            "generated_at": int(now),
            "feed_status": "disabled",
            "scanned_dependencies": 0,
            "unpinned_dependencies": unpinned,
            "vulnerabilities": [],
            "cve_count": 0,
            "errors": [],
        }
        _SCAN_CACHE["ts"] = now
        _SCAN_CACHE["result"] = result
        return result

    # Query OSV in parallel to reduce page load latency for supply-chain views.
    worker_count = min(12, max(1, len(deps)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_dep = {executor.submit(_query_osv_for_dep, dep): dep for dep in deps}
        for future in as_completed(future_to_dep):
            dep = future_to_dep[future]
            try:
                vulns, err = future.result()
            except Exception as exc:  # defensive guard for worker failures
                vulns, err = [], str(exc)
            vulnerabilities.extend(vulns)
            if err:
                errors.append(f'{dep["ecosystem"]}:{dep["name"]}@{dep["version"]}: {err}')

    seen = set()
    unique_vulns: list[dict[str, Any]] = []
    for vuln in vulnerabilities:
        key = (vuln["id"], vuln["package_name"], vuln["package_version"])
        if key in seen:
            continue
        seen.add(key)
        unique_vulns.append(vuln)

    feed_status = "ok"
    if errors and not unique_vulns:
        feed_status = "unavailable"
    elif errors:
        feed_status = "partial"

    result = {
        "generated_at": int(now),
        "feed_status": feed_status,
        "scanned_dependencies": len(deps),
        "unpinned_dependencies": unpinned,
        "vulnerabilities": unique_vulns,
        "cve_count": len(unique_vulns),
        "errors": errors[:20],
    }
    _SCAN_CACHE["ts"] = now
    _SCAN_CACHE["result"] = result
    return result
