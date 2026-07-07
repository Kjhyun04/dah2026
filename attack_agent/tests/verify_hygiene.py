"""Repository hygiene checks: UTF-8, markdown BOM, secrets, and required docs."""

from __future__ import annotations
_import_sys=__import__('sys'); _import_os=__import__('os')
from pathlib import Path as _Path
_REPO=_Path(__file__).resolve().parents[1]
if str(_REPO) not in _import_sys.path: _import_sys.path.insert(0,str(_REPO))
_import_os.chdir(_REPO)  # cwd=repo root → cwd-relative paths resolve

import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

ROOT = Path(__file__).resolve().parents[1]
DOC_ROOT = ROOT.parent / "attack_agent_구축과정"
SCAN_ROOTS = (ROOT, DOC_ROOT)
IGNORE_PARTS = {".venv", "__pycache__", ".git"}

TEXT_EXTS = {
    ".py",
    ".md",
    ".yaml",
    ".yml",
    ".toml",
    ".json",
    ".txt",
    ".html",
    ".js",
    ".css",
    ".sh",
}
# U+FFFD replacement char + known mojibake tokens seen in prior corrupted comments.
MOJIBAKE_MARKERS = ("\ufffd", "쨌", "짠", "븧", "먥")
SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"sk-or-v1-[A-Za-z0-9]{20,}"),
    re.compile(r"api_key\\s*=\\s*[\"'][^\"']+[\"']", re.IGNORECASE),
)
FORBIDDEN_PATHS = (
    ROOT / "generate_code.py",
    ROOT / ".cache_verify",
    ROOT / ".claude",
    DOC_ROOT / "구현종합_20260706_P5P6.md",
    DOC_ROOT / "구현종합_20260706_reap-PhaseA-P4.md",
)

# Any routable public IPv4 leaks the (former) testbed server address; docs must
# use <TESTBED_IP>/<server-ip> placeholders instead. Private/reserved/RFC-5737
# documentation ranges are allowed.
_PUBLIC_IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")


def _is_public_ip(ip: str) -> bool:
    o = [int(x) for x in ip.split(".")]
    if any(v > 255 for v in o):
        return False  # not a valid dotted-quad (e.g. a version string)
    a, b, c = o[0], o[1], o[2]
    if a in (0, 10, 127, 255):
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    if 224 <= a <= 239:
        return False
    if (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113)):
        return False  # RFC 5737 documentation ranges
    return True


def _iter_text_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in IGNORE_PARTS for part in p.parts):
            continue
        if p.name == "verify_hygiene.py":
            continue
        if p.suffix.lower() not in TEXT_EXTS:
            continue
        yield p


def main() -> int:
    fails: list[str] = []

    # 1) UTF-8 decode check
    for base in SCAN_ROOTS:
        for p in _iter_text_files(base):
            try:
                _ = p.read_text(encoding="utf-8")
            except Exception as e:
                fails.append(f"utf8 decode fail: {p} ({type(e).__name__})")

    # 2) markdown BOM check (Windows default-console readability)
    for base in SCAN_ROOTS:
        for p in _iter_text_files(base):
            if p.suffix.lower() != ".md":
                continue
            raw = p.read_bytes()
            if not raw.startswith(b"\xef\xbb\xbf"):
                fails.append(f"markdown utf8-bom missing: {p}")

    # 3) mojibake marker check
    for base in SCAN_ROOTS:
        for p in _iter_text_files(base):
            text = p.read_text(encoding="utf-8", errors="ignore")
            for mk in MOJIBAKE_MARKERS:
                if mk in text:
                    fails.append(f"mojibake marker '{mk}' found: {p}")
                    break

    # 4) obvious hardcoded secret patterns
    for base in SCAN_ROOTS:
        for p in _iter_text_files(base):
            text = p.read_text(encoding="utf-8", errors="ignore")
            for pat in SECRET_PATTERNS:
                if pat.search(text):
                    fails.append(f"possible hardcoded secret pattern '{pat.pattern}' found: {p}")
                    break

    # 5) required documentation entry points
    required = [ROOT / "README.md"]
    # Deploy-only environments may not include sibling design-doc repository.
    if DOC_ROOT.exists():
        required.extend([DOC_ROOT / "README.md", DOC_ROOT / "00_INDEX.md"])
    for p in required:
        if not p.exists():
            fails.append(f"missing required doc: {p}")

    # 6) local/temporary artifacts should not be committed as project state
    for p in FORBIDDEN_PATHS:
        if p.exists():
            fails.append(f"forbidden project artifact present: {p}")

    # 7) cache artifacts should not remain in repository tree
    for base in SCAN_ROOTS:
        if not base.exists():
            continue
        for p in base.rglob("__pycache__"):
            if p.is_dir() and not any(part in IGNORE_PARTS for part in p.parts):
                fails.append(f"cache directory present: {p}")
        for p in base.rglob("*.pyc"):
            if p.is_file() and not any(part in IGNORE_PARTS for part in p.parts):
                fails.append(f"cache bytecode present: {p}")

    # 8) real public IPv4 must not be committed (use <TESTBED_IP> placeholder)
    for base in SCAN_ROOTS:
        for p in _iter_text_files(base):
            text = p.read_text(encoding="utf-8", errors="ignore")
            for m in _PUBLIC_IP_RE.findall(text):
                if _is_public_ip(m):
                    fails.append(f"public IP literal '{m}' found (use placeholder): {p}")
                    break

    if fails:
        print(f"FAIL ({len(fails)})")
        for f in fails:
            print(f"- {f}")
        return 1

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
