def finding_to_markdown(finding) -> str:
    return f"### {finding.title}\n\nSeverity: {finding.severity}\n\n{finding.description}\n"
