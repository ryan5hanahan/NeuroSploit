"""Juice Shop benchmark target definition."""

import os

from benchmark.targets.base_target import BenchmarkTarget


class JuiceShopTarget(BenchmarkTarget):
    """OWASP Juice Shop — intentionally vulnerable Node.js web application.

    Reference: https://owasp.org/www-project-juice-shop/
    Docker:    docker run -p 3000:3000 bkimminich/juice-shop:latest
    """

    name = "juice_shop"
    docker_image = "bkimminich/juice-shop:latest"
    port = 3000

    def get_objective(self) -> str:
        return (
            "Find security vulnerabilities in OWASP Juice Shop. "
            "Target the following vulnerability classes: SQL injection (login form, search), "
            "reflected XSS (search), DOM XSS (hash parameter), stored XSS (feedback), "
            "IDOR (basket and user APIs), broken authentication (JWT none-algorithm, admin panel), "
            "sensitive data exposure (FTP directory, confidential documents), "
            "path traversal (null byte bypass), XXE (complaint file upload), "
            "SSRF (profile image URL), NoSQL injection (reviews), open redirect, "
            "CSRF, and mass assignment. "
            "For each finding call report_finding with vuln_type, endpoint, parameter, "
            "severity, and a description including proof-of-concept details."
        )

    def get_healthcheck_url(self) -> str:
        return "http://juice-shop:3000"

    def get_ground_truth_path(self) -> str:
        return os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "ground_truth",
            "juice_shop.yaml",
        )
