from __future__ import annotations

import os


async def authenticate(page, config):
    username = os.environ["SECSCAN_GITHUB_USERNAME"]
    password = os.environ["SECSCAN_GITHUB_PASSWORD"]
    await page.goto("https://github.com/login", wait_until="domcontentloaded")
    await page.fill("#login_field", username)
    await page.fill("#password", password)
    await page.click('input[name="commit"]')
    await page.wait_for_url(lambda url: "/login" not in url, wait_until="domcontentloaded", timeout=20000)
    if "/login" in page.url:
        raise RuntimeError("GitHub login did not leave the login page")
