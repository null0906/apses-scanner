from __future__ import annotations


async def authenticate(page, config):
    await page.goto("http://localhost:4280/login.php", wait_until="networkidle")
    await page.fill('input[name="username"]', "admin")
    await page.fill('input[name="password"]', "password")
    await page.click('input[type="submit"]')
    await page.wait_for_load_state("networkidle")
    if "login.php" in page.url:
        raise RuntimeError("DVWA login failed")
