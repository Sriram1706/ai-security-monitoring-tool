#!/usr/bin/env python3
import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None


IST = ZoneInfo("Asia/Kolkata") if ZoneInfo else timezone(timedelta(hours=5, minutes=30))
UTC = timezone.utc

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "backups",
    "exports",
    "__pycache__",
    ".venv",
    "venv",
}


@dataclass
class Config:
    project_root: Path
    doc_path: Path
    state_path: Path
    note: str
    max_files: int
    include_roots: List[str]
    bootstrap_hours: int


def parse_args() -> Config:
    default_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Auto-capture changed files and append a dated entry to docs/work_carried_out_detailed.md"
    )
    parser.add_argument("--project-root", default=str(default_root), help="Tool project root")
    parser.add_argument("--doc-path", default="", help="Override work history markdown path")
    parser.add_argument("--state-path", default="", help="Override state JSON path")
    parser.add_argument("--note", default="Automated history capture", help="Short note for this capture entry")
    parser.add_argument("--max-files", type=int, default=120, help="Max files to include in entry")
    parser.add_argument(
        "--include",
        default="frontend,backend,scripts,docs,deploy",
        help="Comma-separated top-level folders to scan",
    )
    parser.add_argument(
        "--bootstrap-hours",
        type=int,
        default=24,
        help="On first run (no state), capture changes in the past N hours",
    )
    args = parser.parse_args()

    root = Path(args.project_root).resolve()
    doc_path = Path(args.doc_path).resolve() if args.doc_path else root / "docs" / "work_carried_out_detailed.md"
    state_path = Path(args.state_path).resolve() if args.state_path else root / "docs" / ".work_history_state.json"
    include_roots = [item.strip() for item in str(args.include).split(",") if item.strip()]
    return Config(
        project_root=root,
        doc_path=doc_path,
        state_path=state_path,
        note=str(args.note).strip(),
        max_files=max(10, int(args.max_files)),
        include_roots=include_roots,
        bootstrap_hours=max(1, int(args.bootstrap_hours)),
    )


def load_state(path: Path) -> Dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(path: Path, state: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def compute_since(state: Dict, bootstrap_hours: int) -> datetime:
    raw = str(state.get("last_capture_utc") or "").strip()
    if raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)
        except Exception:
            pass
    return datetime.now(tz=UTC) - timedelta(hours=bootstrap_hours)


def collect_changed_files(cfg: Config, since_utc: datetime) -> List[Path]:
    changed: List[Path] = []
    for top in cfg.include_roots:
        root = cfg.project_root / top
        if not root.exists() or not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
            for name in filenames:
                if len(changed) >= cfg.max_files:
                    return sorted(changed, key=lambda p: p.as_posix())
                fp = Path(dirpath) / name
                try:
                    mtime = datetime.fromtimestamp(fp.stat().st_mtime, tz=UTC)
                except Exception:
                    continue
                if mtime > since_utc:
                    changed.append(fp)
    return sorted(changed, key=lambda p: p.as_posix())


def group_files(project_root: Path, files: List[Path]) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {}
    for fp in files:
        try:
            rel = fp.relative_to(project_root).as_posix()
        except Exception:
            rel = fp.as_posix()
        area = rel.split("/", 1)[0] if "/" in rel else "root"
        grouped.setdefault(area, []).append(rel)
    return grouped


def ensure_doc_exists(doc_path: Path) -> None:
    if doc_path.exists():
        return
    doc_path.parent.mkdir(parents=True, exist_ok=True)
    doc_path.write_text(
        "# AI Security Monitoring Tool - End-to-End Work History (From Project Start)\n\n"
        f"Last updated: {datetime.now(tz=IST).strftime('%Y-%m-%d')}\n\n"
        "## Auto Capture Log\n",
        encoding="utf-8",
    )


def build_entry(note: str, since_utc: datetime, grouped: Dict[str, List[str]], total: int) -> str:
    now_ist = datetime.now(tz=IST)
    now_utc = datetime.now(tz=UTC)
    lines = []
    lines.append("\n---\n")
    lines.append(f"## Auto Update - {now_ist.strftime('%Y-%m-%d %H:%M:%S IST')}\n")
    lines.append(f"- Capture note: {note or 'Automated history capture'}")
    lines.append(f"- Window start (UTC): {since_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"- Captured at (UTC): {now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"- Changed files detected: {total}\n")

    if total == 0:
        lines.append("No file changes detected in the configured scan roots.")
        return "\n".join(lines) + "\n"

    lines.append("### Changed file summary by area")
    for area in sorted(grouped.keys()):
        files = grouped[area]
        preview = files[:20]
        lines.append(f"- {area}: {len(files)} file(s)")
        for rel in preview:
            lines.append(f"  - `{rel}`")
        if len(files) > len(preview):
            lines.append(f"  - `... and {len(files) - len(preview)} more`")
    return "\n".join(lines) + "\n"


def main() -> int:
    cfg = parse_args()
    ensure_doc_exists(cfg.doc_path)
    state = load_state(cfg.state_path)
    since_utc = compute_since(state, cfg.bootstrap_hours)
    files = collect_changed_files(cfg, since_utc)
    grouped = group_files(cfg.project_root, files)
    entry = build_entry(cfg.note, since_utc, grouped, len(files))

    with cfg.doc_path.open("a", encoding="utf-8") as f:
        f.write(entry)

    save_state(
        cfg.state_path,
        {
            "last_capture_utc": datetime.now(tz=UTC).isoformat(),
            "last_note": cfg.note,
            "include_roots": cfg.include_roots,
            "max_files": cfg.max_files,
            "last_count": len(files),
        },
    )

    print(
        json.dumps(
            {
                "status": "ok",
                "doc_path": str(cfg.doc_path),
                "state_path": str(cfg.state_path),
                "changed_files": len(files),
                "captured_at_utc": datetime.now(tz=UTC).isoformat(),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

