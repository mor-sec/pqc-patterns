"""MkDocs hook that publishes the repo's own READMEs as site pages.

Each patterns/<dir>/README.md becomes patterns/<dir>.md and rules/README.md
becomes checker.md, so the site and GitHub never drift apart. Relative links
are rewritten: links to another pattern or to the checker stay on the site,
and links to code go to the file on GitHub. The pattern list in the
navigation is built from the same READMEs, so a new pattern shows up without
editing mkdocs.yml.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path

from mkdocs.config.defaults import MkDocsConfig
from mkdocs.structure.files import File, Files

REPO = Path(__file__).resolve().parents[1]
LINK = re.compile(r"(\]\()([^)\s]+)(\))")
PATTERNS_NAV = "Patterns"


def _patterns() -> list[tuple[str, str]]:
    """(directory name, H1 title) for every pattern, in ID order."""
    out = []
    for readme in sorted(REPO.glob("patterns/*/README.md")):
        title = readme.read_text(encoding="utf-8").splitlines()[0].removeprefix("# ").strip()
        title = re.sub(r"\s*\([^)]*\)$", "", title)  # keep nav labels short
        out.append((readme.parent.name, title))
    return out


def _site_page(repo_path: str) -> str | None:
    """The site page for a repo directory, if it has one."""
    repo_path = repo_path.rstrip("/")
    if repo_path == "rules":
        return "checker.md"
    parts = repo_path.split("/")
    if len(parts) == 2 and parts[0] == "patterns" and (REPO / repo_path / "README.md").is_file():
        return f"patterns/{parts[1]}.md"
    return None


def rewrite_links(markdown: str, source: str, page: str, blob_url: str) -> str:
    """Rewrite relative links in `source` (a repo path) for the site page `page`."""

    def fix(m: re.Match[str]) -> str:
        target = m.group(2)
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
            return m.group(0)
        path, _, anchor = target.partition("#")
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), path))
        if resolved.startswith(".."):
            raise ValueError(f"{source}: link {target!r} leaves the repository")
        site = _site_page(resolved)
        if site is not None:
            new = posixpath.relpath(site, posixpath.dirname(page))
        else:
            kind = "tree" if (REPO / resolved).is_dir() else "blob"
            if not (REPO / resolved).exists():
                raise ValueError(f"{source}: link {target!r} points at a missing file")
            new = f"{blob_url}/{kind}/main/{resolved}"
        if anchor:
            new += "#" + anchor
        return m.group(1) + new + m.group(3)

    return LINK.sub(fix, markdown)


def on_config(config: MkDocsConfig) -> MkDocsConfig:
    entries: list = [{"Overview": "patterns/index.md"}]
    entries += [{title: f"patterns/{d}.md"} for d, title in _patterns()]
    for i, item in enumerate(config.nav or []):
        if isinstance(item, dict) and PATTERNS_NAV in item:
            config.nav[i] = {PATTERNS_NAV: entries}
    return config


def on_files(files: Files, config: MkDocsConfig) -> Files:
    blob_url = config.repo_url.rstrip("/")
    sources = {f"patterns/{d}/README.md": f"patterns/{d}.md" for d, _ in _patterns()}
    sources["rules/README.md"] = "checker.md"
    for source, page in sources.items():
        text = (REPO / source).read_text(encoding="utf-8")
        files.append(File.generated(config, page, content=rewrite_links(text, source, page, blob_url)))

    # The pattern index is the table from the root README, so it stays in step too.
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Patterns", 1)[1].split("\n## ", 1)[0]
    table = "\n".join(line for line in section.splitlines() if line.startswith("|"))
    intro = "Each pattern page has the same sections. [Start here](../guide/index.md) explains them.\n\n"
    index = "# Patterns\n\n" + intro + rewrite_links(table, "README.md", "patterns/index.md", blob_url)
    files.append(File.generated(config, "patterns/index.md", content=index))
    return files
