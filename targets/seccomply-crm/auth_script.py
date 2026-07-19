from __future__ import annotations

import os


async def authenticate(page, config):
    email = os.environ["SECSCAN_TIER1_EMAIL"]
    password = os.environ["SECSCAN_TIER1_PASSWORD"]
    await page.goto(f"{config.target.base_url}/login", wait_until="domcontentloaded")
    await page.fill("#email", email)
    await page.fill("#password", password)
    await page.click('button[type="submit"]')
    await page.wait_for_url(lambda url: "/login" not in url, timeout=15000)
    if "/login" in page.url:
        raise RuntimeError("SecComply CRM login did not leave the login page")
