SECRET_PATTERNS = {
    "jwt": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "generic_secret": r"(?i)(api[_-]?key|secret|token|password)[\"'\s:=]+[\"']?[A-Za-z0-9_./+=-]{16,}",
    "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
}
ERROR_LEAK_PATTERNS = ["traceback", "stack trace", "sequelize", "dialects/sqlite", "sqlite/query.js", "exception"]
