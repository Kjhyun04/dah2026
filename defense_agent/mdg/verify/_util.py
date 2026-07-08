"""Shared helpers for verify-suite scripts (pure stdlib; no langgraph/pydantic req)."""
from __future__ import annotations

import ast
import os
import sys

MDG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))          # .../mdg
CORE = os.path.join(MDG_ROOT, "core")
NODES = os.path.join(CORE, "nodes")


def read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def parse(path: str) -> ast.Module:
    return ast.parse(read(path), filename=path)


def py_files(directory: str) -> list[str]:
    out = []
    for name in sorted(os.listdir(directory)):
        if name.endswith(".py") and name != "__init__.py":
            out.append(os.path.join(directory, name))
    return out


class Report:
    def __init__(self, name: str):
        self.name = name
        self.fails: list[str] = []
        self.checks = 0

    def check(self, cond: bool, msg: str) -> None:
        self.checks += 1
        if not cond:
            self.fails.append(msg)

    def done(self) -> int:
        if self.fails:
            print(f"[FAIL] {self.name}: {len(self.fails)}/{self.checks} checks failed")
            for f in self.fails:
                print(f"   - {f}")
            return 1
        print(f"[PASS] {self.name}: {self.checks} checks")
        return 0


def run(fn) -> None:
    rep = fn()
    sys.exit(rep.done())
