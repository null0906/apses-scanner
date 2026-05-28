PLAYBOOK = {
    "sqli": "Verify manually with a safe baseline and parameterized payloads. Confirm data access or query error impact before reporting.",
    "headers": "Confirm headers on representative routes and add application/framework-level security header configuration.",
    "data": "Confirm the exposed value is sensitive, determine role/tenant scope, and remove or redact it from responses.",
    "xss": "Reproduce in a browser-rendered context and confirm script execution before reporting.",
    "jwt": "Replay token mutations against protected endpoints and confirm accepted tampering before reporting.",
    "ssrf": "Use approved callback infrastructure and confirm an outbound interaction or returned metadata.",
    "authz": "Validate with two or more roles/users and confirm object-level authorization failure.",
    "redirect": "Confirm the application redirects to an attacker-controlled destination.",
    "auth": "Verify authentication behavior manually with lockout/session controls in scope.",
}

def guidance(check_name: str) -> str:
    return PLAYBOOK.get(check_name, "Verify manually before adding to a client report.")
