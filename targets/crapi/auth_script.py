async def authenticate(page, config):
    await page.goto("http://localhost:8888/login", wait_until="domcontentloaded")
    
    # Wait for the email input to actually be visible and ready
    await page.wait_for_selector('#basic_email', state='visible', timeout=15000)
    await page.wait_for_timeout(1000)
    
    # Use evaluate to set value and trigger React synthetic events
    await page.evaluate("""
        (function() {
            const emailInput = document.getElementById('basic_email');
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value').set;
            nativeInputValueSetter.call(emailInput, 'victim@example.com');
            emailInput.dispatchEvent(new Event('input', { bubbles: true }));
            emailInput.dispatchEvent(new Event('change', { bubbles: true }));
        })()
    """)
    
    await page.evaluate("""
        (function() {
            const pwInput = document.getElementById('basic_password');
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value').set;
            nativeInputValueSetter.call(pwInput, 'Victim1234!');
            pwInput.dispatchEvent(new Event('input', { bubbles: true }));
            pwInput.dispatchEvent(new Event('change', { bubbles: true }));
        })()
    """)
    
    await page.wait_for_timeout(500)
    await page.click('button[type="submit"]')
    
    # Wait for navigation away from login
    try:
        await page.wait_for_url(
            lambda url: "login" not in url.lower(), 
            timeout=10000
        )
    except Exception:
        pass
    
    if "login" in page.url.lower():
        raise RuntimeError(f"crAPI login failed, still on {page.url}")
