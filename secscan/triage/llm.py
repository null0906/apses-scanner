PROMPTS = {
    "sqli": "Explain SQL injection evidence, impact, and remediation without overstating unverified access.",
    "headers": "Summarize missing security headers and practical remediation.",
    "data": "Assess sensitive data exposure evidence and manual validation steps.",
    "xss": "Describe reflected/DOM XSS validation steps.",
    "jwt": "Describe JWT tampering validation and remediation.",
    "ssrf": "Describe SSRF confirmation requirements.",
    "authz": "Describe object authorization validation.",
    "redirect": "Describe open redirect confirmation.",
    "auth": "Describe authentication control validation.",
}

def prompt_for(check_name: str) -> str:
    return PROMPTS.get(check_name, "Triage this finding cautiously and require manual verification.")
