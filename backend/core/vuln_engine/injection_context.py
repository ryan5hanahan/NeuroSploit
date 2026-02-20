"""
sploit.ai - Injection Context Detection

Provides database type detection from error messages and injection
context classification for payload selection.
"""

import re
from enum import Enum
from typing import Optional


class InjectionContext(Enum):
    """Context where payload will be injected."""
    URL_PARAMETER = "url_parameter"
    POST_BODY = "post_body"
    HTTP_HEADER = "http_header"
    COOKIE = "cookie"
    JSON_VALUE = "json_value"
    XML_VALUE = "xml_value"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_CONTENT = "html_content"


# Database error signature patterns
_DB_SIGNATURES = {
    "mysql": [
        re.compile(r"mysql", re.I),
        re.compile(r"sql syntax.*mysql", re.I),
        re.compile(r"mysql_fetch", re.I),
        re.compile(r"mysqli", re.I),
        re.compile(r"MariaDB", re.I),
        re.compile(r"SQLSTATE\[HY000\]", re.I),
        re.compile(r"You have an error in your SQL syntax", re.I),
    ],
    "postgres": [
        re.compile(r"postgresql", re.I),
        re.compile(r"pg_query", re.I),
        re.compile(r"pg_exec", re.I),
        re.compile(r"psql", re.I),
        re.compile(r"PG::SyntaxError", re.I),
        re.compile(r"ERROR:\s+syntax error at or near", re.I),
    ],
    "mssql": [
        re.compile(r"microsoft sql", re.I),
        re.compile(r"mssql", re.I),
        re.compile(r"sql server", re.I),
        re.compile(r"odbc.*sql server", re.I),
        re.compile(r"Unclosed quotation mark", re.I),
        re.compile(r"SqlClient", re.I),
    ],
    "oracle": [
        re.compile(r"oracle", re.I),
        re.compile(r"ORA-\d{5}", re.I),
        re.compile(r"plsql", re.I),
        re.compile(r"oci_", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
    ],
    "sqlite": [
        re.compile(r"sqlite", re.I),
        re.compile(r"sqlite3", re.I),
        re.compile(r"SQLITE_ERROR", re.I),
        re.compile(r"SQLite3::SQLException", re.I),
    ],
}


def detect_db_type(error_msg: str) -> Optional[str]:
    """Detect database type from error message content.

    Args:
        error_msg: Error message string from the server response.

    Returns:
        Database type string (mysql, postgres, mssql, oracle, sqlite)
        or None if no match.
    """
    if not error_msg:
        return None

    for db_type, patterns in _DB_SIGNATURES.items():
        for pattern in patterns:
            if pattern.search(error_msg):
                return db_type

    return None
