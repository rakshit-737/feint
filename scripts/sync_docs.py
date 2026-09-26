"""Copy repo-root documents and result artefacts into docs/ for the MkDocs site.

Links that point outside docs/ are rewritten to GitHub URLs; figures and report JSON are copied
under docs/assets/ and docs/demo/. Run before `mkdocs build` (the docs workflow does).
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
GH = "https://github.com/rakshit-737/feint/blob/main/"
PAGES = {"THREAT_MODEL.md": "threat-model.md", "SECURITY.md": "security.md", "CHANGELOG.md": "changelog.md"}


def rewrite(text: str) -> str:
    def fix(m):
        label, target = m.group(1), m.group(2)
        if re.match(r"^(https?:|#|mailto:)", target):
            return m.group(0)
        if target.startswith("docs/"):
            return f"[{label}]({target[5:]})"
        return f"[{label}]({GH}{target})"

    return re.sub(r"\[([^\]]*)\]\(([^)\s]+)\)", fix, text)


def main():
    for src, dst in PAGES.items():
        (DOCS / dst).write_text(rewrite((ROOT / src).read_text(encoding="utf-8")), encoding="utf-8")
    for ds in ("cicids2017", "unsw_nb15"):
        src = ROOT / "results" / ds
        out = DOCS / "assets" / ds
        out.mkdir(parents=True, exist_ok=True)
        for f in src.glob("*.png"):
            shutil.copy2(f, out / f.name)
        demo = DOCS / "demo" / "data"
        demo.mkdir(parents=True, exist_ok=True)
        for name in ("report.json", "seeds.json"):
            if (src / name).exists():
                shutil.copy2(src / name, demo / f"{ds}_{name}")
    print("docs synced")


if __name__ == "__main__":
    main()
