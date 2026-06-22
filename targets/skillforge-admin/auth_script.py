from __future__ import annotations

import os


async def authenticate(page, config):
    await page.goto(f"{config.target.base_url}/login", wait_until="domcontentloaded")
    await page.fill("#email", os.environ["SECSCAN_SKILLFORGE_ADMIN_EMAIL"])
    await page.fill("#password", os.environ["SECSCAN_SKILLFORGE_ADMIN_PASSWORD"])
    await page.click('button[type="submit"]')
    await page.wait_for_url(lambda url: "/login" not in url, wait_until="domcontentloaded", timeout=15000)
    if "/login" in page.url:
        raise RuntimeError("SkillForge admin login did not leave the login page")
