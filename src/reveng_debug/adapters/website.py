"""Website clone inventory (SPEC-RD-007). Static HTML plus gotcontext-chrome captures."""

from __future__ import annotations

import json
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from reveng_debug.contracts.models import (
    CapabilityStatus,
    ClaimConfidence,
    EvidenceAuthority,
    InventoryResult,
    Location,
    TargetKind,
    WebsiteCapture,
)
from reveng_debug.ledger.service import Ledger

MAX_FETCH_BYTES = 2_000_000
FETCH_TIMEOUT_S = 20


class _AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []
        self.images: list[str] = []
        self.title_bits: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): v for k, v in attrs}
        if tag == "script" and ad.get("src"):
            self.scripts.append(ad["src"] or "")
        elif tag == "link" and (ad.get("rel") or "").lower() == "stylesheet" and ad.get("href"):
            self.stylesheets.append(ad["href"] or "")
        elif tag == "img" and ad.get("src"):
            self.images.append(ad["src"] or "")
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_bits.append(data)


def parse_html(html: str, base_url: str | None = None) -> WebsiteCapture:
    parser = _AssetParser()
    parser.feed(html)
    scripts = [_abs(base_url, s) for s in parser.scripts if s]
    styles = [_abs(base_url, s) for s in parser.stylesheets if s]
    images = [_abs(base_url, s) for s in parser.images if s]
    title = "".join(parser.title_bits).strip() or None
    return WebsiteCapture(
        backend="static-html",
        url=base_url,
        title=title,
        html=html,
        scripts=scripts,
        stylesheets=styles,
        images=images,
    )


def load_capture(path: Path) -> WebsiteCapture:
    if path.suffix.lower() in {".html", ".htm"}:
        html = path.read_text(encoding="utf-8", errors="replace")
        return parse_html(html, base_url=None)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and payload.get("html") and not payload.get("scripts"):
        raw_url = payload.get("url")
        base = raw_url if isinstance(raw_url, str) else None
        parsed = parse_html(str(payload["html"]), base)
        payload.setdefault("scripts", parsed.scripts)
        payload.setdefault("stylesheets", parsed.stylesheets)
        payload.setdefault("images", parsed.images)
        payload.setdefault("title", parsed.title)
    return WebsiteCapture.model_validate(payload)


def fetch_url(url: str) -> WebsiteCapture:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("only http(s) URLs may be fetched")
    request = Request(url, headers={"User-Agent": "reveng-debug/0.1 website-clone"})
    with urlopen(request, timeout=FETCH_TIMEOUT_S) as response:  # noqa: S310 — scheme checked
        raw = response.read(MAX_FETCH_BYTES + 1)
        charset = response.headers.get_content_charset() or "utf-8"
    if len(raw) > MAX_FETCH_BYTES:
        raise ValueError("response exceeded 2 MiB cap")
    html = raw.decode(charset, errors="replace")
    capture = parse_html(html, base_url=url)
    capture.url = url
    capture.backend = "static-html"
    return capture


def clone_website(source: Path | WebsiteCapture, ledger: Ledger) -> InventoryResult:
    capture = source if isinstance(source, WebsiteCapture) else load_capture(source)
    clone_dir = ledger.store.artifacts / "website-clone"
    clone_dir.mkdir(parents=True, exist_ok=True)
    (clone_dir / "capture.json").write_text(capture.model_dump_json(indent=2), encoding="utf-8")
    if capture.html:
        (clone_dir / "index.html").write_text(capture.html, encoding="utf-8")
    (clone_dir / "tokens.json").write_text(json.dumps(capture.tokens, indent=2), encoding="utf-8")
    (clone_dir / "assets.json").write_text(
        json.dumps(
            {
                "scripts": capture.scripts,
                "stylesheets": capture.stylesheets,
                "images": capture.images,
                "assets": capture.assets,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (clone_dir / "components.json").write_text(
        json.dumps(capture.components, indent=2), encoding="utf-8"
    )
    (clone_dir / "reconstruction.md").write_text(
        _reconstruction_markdown(capture), encoding="utf-8"
    )

    live = capture.backend == "gotcontext-chrome"
    authority = EvidenceAuthority.CONTROLLED_REPLAY if live else EvidenceAuthority.SHIPPED_ARTIFACT
    ledger.record(
        confidence=ClaimConfidence.SEEN,
        kind="website.clone",
        statement=(
            f"cloned {capture.url or 'local snapshot'} via {capture.backend}; "
            f"{len(capture.scripts)} scripts, {len(capture.stylesheets)} stylesheets"
        ),
        tool=capture.backend,
        command="reveng-debug clone-website",
        location=Location(path=str(clone_dir)),
        authority=authority,
        limitations=_limitations(capture),
        metadata={"title": capture.title},
    )
    if not capture.tokens:
        ledger.record(
            confidence=ClaimConfidence.UNKNOWN,
            kind="website.tokens",
            statement="no design tokens in this capture; run gotcontext extract_design_tokens",
            tool="gotcontext-chrome",
            limitations=["static HTML has no computed CSS variables"],
        )
    findings: dict[str, Any] = {
        "url": capture.url,
        "title": capture.title,
        "backend": capture.backend,
        "scripts": capture.scripts,
        "stylesheets": capture.stylesheets,
        "images": capture.images[:50],
        "token_keys": list(capture.tokens)[:40] if isinstance(capture.tokens, dict) else [],
        "component_count": len(capture.components),
        "clone_dir": str(clone_dir),
    }
    return InventoryResult(
        session_id=ledger.store.session_id,
        target_kind=TargetKind.WEBSITE,
        original_path=str(source) if isinstance(source, Path) else capture.url or "",
        workspace_path=str(clone_dir),
        status=CapabilityStatus.PRESENT,
        engine=capture.backend,
        coverage="html-assets,tokens,components,reconstruction-brief",
        findings=findings,
        evidence=ledger.all(),
        limitations=_limitations(capture),
    )


def _abs(base: str | None, ref: str) -> str:
    if not base:
        return ref
    return urljoin(base, ref)


def _limitations(capture: WebsiteCapture) -> list[str]:
    notes = [
        "does not copy a live backend, auth, or cookies",
        "static fetch does not run page JavaScript",
    ]
    if capture.backend != "gotcontext-chrome":
        notes.append(
            "live layout/tokens/assets require gotcontext-chrome capture JSON "
            "(see skills/reveng-debug/SKILL.md)"
        )
    return notes


def _reconstruction_markdown(capture: WebsiteCapture) -> str:
    scripts = "\n".join(f"- `{s}`" for s in capture.scripts) or "- unknown"
    styles = "\n".join(f"- `{s}`" for s in capture.stylesheets) or "- unknown"
    return f"""# Website reconstruction brief

**Spec ID:** SPEC-RD-007
**PRD:** Clone visible structure of an authorized site into a local package.
**Backend:** `{capture.backend}`
**URL:** {capture.url or "local snapshot"}
**Title:** {capture.title or "unknown"}

## Scripts
{scripts}

## Stylesheets
{styles}

## Tokens
Captured token keys: {", ".join(list(capture.tokens)[:30]) or "none (run extract_design_tokens)"}

## Components
{len(capture.components)} component skeletons in `components.json`.

## Junior rebuild
1. Recreate layout from `index.html` + stylesheets.
2. Apply tokens from `tokens.json`.
3. Mock data only — do not replay captured credentials.
4. Mark unseen behavior **unknown**, not absent.
"""
