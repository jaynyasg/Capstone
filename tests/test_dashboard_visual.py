"""Opt-in visual smoke tests for the dashboard sections.

Run with:
    uv run --extra visual pytest -m visual tests/test_dashboard_visual.py

If Playwright's browser is not installed yet:
    uv run --extra visual playwright install chromium

Set AEGIS_VISUAL_ARTIFACTS_DIR to keep section screenshots outside pytest's temp dir.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest

from aegis.dashboard.render import render_html
from tests.test_dashboard import SAMPLE_CASES, SAMPLE_PLATFORM

pytestmark = pytest.mark.visual

SECTION_KEYS = [
    "evidence-health",
    "investigate",
    "platform-cockpit",
    "nimbus-rankings",
    "recent-decisions",
    "eval-summary",
    "success-criteria",
    "baseline-vs-protected",
    "detector-hit-distribution",
]


def _artifact_dir(tmp_path: Path) -> Path:
    configured = os.environ.get("AEGIS_VISUAL_ARTIFACTS_DIR")
    path = Path(configured) if configured else tmp_path / "dashboard-visual"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _browser(playwright: Any):
    try:
        return playwright.chromium.launch()
    except Exception as exc:  # noqa: BLE001 - browser install errors differ by platform.
        pytest.skip(
            "Playwright Chromium is not installed; run "
            "`uv run --extra visual playwright install chromium` "
            f"({exc})"
        )


def _section_clip(page: Any, section_key: str) -> dict[str, float]:
    clip = page.evaluate(
        """
        (sectionKey) => {
          const section = document.querySelector(`section[data-section="${sectionKey}"]`);
          if (!section) throw new Error(`missing section: ${sectionKey}`);
          const sections = Array.from(document.querySelectorAll("section.dashboard-section"));
          const index = sections.indexOf(section);
          const next = sections[index + 1];
          const rect = section.getBoundingClientRect();
          const nextRect = next ? next.getBoundingClientRect() : null;
          const pageHeight = Math.max(
            document.body.scrollHeight,
            document.documentElement.scrollHeight,
            document.documentElement.clientHeight
          );
          const pageWidth = Math.max(
            document.body.scrollWidth,
            document.documentElement.scrollWidth,
            document.documentElement.clientWidth
          );
          const bottom = nextRect ? nextRect.top - 8 : document.body.scrollHeight;
          const y = Math.max(0, Math.floor(rect.top + window.scrollY - 8));
          const rawHeight = Math.max(24, Math.ceil(bottom + window.scrollY - y));
          const height = Math.min(rawHeight, Math.max(24, pageHeight - y));
          return {
            x: 0,
            y,
            width: Math.min(pageWidth, 1200),
            height: Math.min(height, 900)
          };
        }
        """,
        section_key,
    )
    return {
        "x": float(clip["x"]),
        "y": float(clip["y"]),
        "width": float(clip["width"]),
        "height": float(clip["height"]),
    }


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def test_dashboard_sections_have_visual_smoke_screenshots(tmp_path: Path) -> None:
    sync_api = pytest.importorskip(
        "playwright.sync_api",
        reason="Install visual extra: uv run --extra visual pytest -m visual",
    )
    html_path = tmp_path / "dashboard.html"
    html_path.write_text(render_html(SAMPLE_PLATFORM, cases=SAMPLE_CASES), encoding="utf-8")
    artifact_dir = _artifact_dir(tmp_path)

    with sync_api.sync_playwright() as playwright:
        browser = _browser(playwright)
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 1200})
            page.goto(html_path.as_uri())
            button = page.locator("#walkthrough-run")
            sync_api.expect(button).to_be_visible()

            for section_key in SECTION_KEYS:
                section = page.locator(f'section[data-section="{section_key}"]')
                sync_api.expect(section).to_be_visible()
                label = section.locator(".label")
                sync_api.expect(label).to_be_visible()
                styles = label.evaluate(
                    """
                    (el) => {
                      const style = window.getComputedStyle(el);
                      return {
                        fontWeight: Number(style.fontWeight),
                        borderLeftWidth: Number.parseFloat(style.borderLeftWidth),
                        color: style.color
                      };
                    }
                    """
                )
                assert styles["fontWeight"] >= 700
                assert styles["borderLeftWidth"] >= 3

                clip = _section_clip(page, section_key)
                assert clip["width"] > 300
                assert clip["height"] > 40
                screenshot = artifact_dir / f"{_slug(section_key)}.png"
                page.screenshot(path=screenshot, clip=clip, full_page=True)
                assert screenshot.stat().st_size > 1_000

            refresh_path = tmp_path / "dashboard-refresh.html"
            refresh_path.write_text(
                render_html(SAMPLE_PLATFORM, cases=SAMPLE_CASES, auto_refresh=2),
                encoding="utf-8",
            )
            page.goto(refresh_path.as_uri())
            button = page.locator("#walkthrough-run")
            sync_api.expect(button).to_be_visible()
            button.click()
            sync_api.expect(page.locator("#walkthrough-status.active")).to_be_visible()
            sync_api.expect(
                page.locator('section[data-section="evidence-health"].walkthrough-active')
            ).to_be_visible()
            sync_api.expect(page.locator(".walkthrough-packet")).to_be_visible()
            overlay_source = page.locator("#walkthrough-status .walkthrough-source")
            sync_api.expect(overlay_source).to_contain_text("snapshot + health")
            sync_api.expect(page.locator("#walkthrough-status .walkthrough-data")).to_contain_text(
                "healthy"
            )
            active_packet = page.locator(
                'section[data-section="evidence-health"] .walkthrough-section-packet'
            )
            sync_api.expect(active_packet).to_be_visible()
            sync_api.expect(active_packet).to_contain_text("Evidence packet arrived")
            sync_api.expect(active_packet).to_contain_text("Prompt/input")
            sync_api.expect(active_packet).to_contain_text("Guard call")
            sync_api.expect(active_packet).to_contain_text("Data query")
            sync_api.expect(active_packet).to_contain_text("Try this prompt")
            sync_api.expect(active_packet).to_contain_text("weekly status report")
            sync_api.expect(active_packet).to_contain_text("Live guard test")
            sync_api.expect(active_packet).to_contain_text("healthy")
            sample_link = active_packet.locator(".walkthrough-sample-link")
            sync_api.expect(sample_link).to_have_attribute(
                "href", re.compile(r"/try\?mode=request")
            )
            assert page.locator("#dashboard-auto-refresh").get_attribute("data-state") == "paused"
            page.wait_for_timeout(2500)
            sync_api.expect(page.locator("#walkthrough-status.active")).to_be_visible()
            sync_api.expect(page.locator("#walkthrough-run")).to_contain_text("Running")
            sync_api.expect(page.locator(".walkthrough-step.active")).to_be_visible()
            current_packet = page.locator("section.walkthrough-active .walkthrough-section-packet")
            sync_api.expect(current_packet).to_contain_text("Prompt/input")
            sync_api.expect(current_packet).to_contain_text("Live guard test")
            active_path = artifact_dir / "walkthrough-first-step.png"
            page.screenshot(path=active_path, full_page=False)
            assert active_path.stat().st_size > 1_000
        finally:
            browser.close()
