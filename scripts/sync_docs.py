"""Copy repo-root documents and result artefacts into docs/ for the MkDocs site.

Links that point outside docs/ are rewritten to GitHub URLs; figures and report JSON are copied
under docs/assets/ and docs/demo/. Run before `mkdocs build` (the docs workflow does).
"""
from __future__ import annotations

import json
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


def section(text: str, start: str, end: str) -> str:
    a = text.index(start)
    b = text.index(end, a)
    return text[a:b]


def readme_pages(readme: str) -> dict[str, str]:
    """Pages built from README sections, so the site never disagrees with the README."""
    fig = re.compile(r"!\[([^\]]*)\]\(results/([^/]+)/([^)]+\.png)\)")
    readme = fig.sub(lambda m: f"![{m.group(1)}](assets/{m.group(2)}/{m.group(3)})", readme)
    ev = ("# Evaluation\n\nMethodology, every result table and its confidence interval. Generated from the "
          "README by `scripts/sync_docs.py`.\n\n"
          + section(readme, "## Headline results", "## How it works").replace("## ", "## ", 1)
          + section(readme, "## Full results", "## Prior art and how FEINT differs"))
    lim = "# Limitations and roadmap\n\n" + section(readme, "## Limitations", "## Repository layout")
    return {"evaluation.md": ev, "limitations.md": lim}


def main():
    for src, dst in PAGES.items():
        (DOCS / dst).write_text(rewrite((ROOT / src).read_text(encoding="utf-8")), encoding="utf-8")
    for dst, text in readme_pages((ROOT / "README.md").read_text(encoding="utf-8")).items():
        (DOCS / dst).write_text(rewrite(text), encoding="utf-8")
    names = []
    for src in sorted(p for p in (ROOT / "results").iterdir() if p.is_dir()):
        ds = src.name
        out = DOCS / "assets" / ds
        out.mkdir(parents=True, exist_ok=True)
        for f in src.glob("*.png"):
            shutil.copy2(f, out / f.name)
        demo = DOCS / "demo" / "data"
        demo.mkdir(parents=True, exist_ok=True)
        for name in ("report.json", "seeds.json", "steal.json"):
            if (src / name).exists():
                shutil.copy2(src / name, demo / f"{ds}_{name}")
        if (src / "report.json").exists():
            names.append(ds)
    (DOCS / "demo" / "data" / "index.json").write_text(json.dumps(names), encoding="utf-8")
    print("docs synced")


if __name__ == "__main__":
    main()
