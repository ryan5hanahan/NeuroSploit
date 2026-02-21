# Custom Techniques

Place your custom technique YAML files in this directory.

## Format

Each YAML file should contain one or more techniques:

```yaml
techniques:
  - id: my_custom_technique
    name: "My Custom Technique"
    vuln_type: sqli  # Must match a canonical vuln type
    description: "Description of the technique"
    severity: high
    technology: ["mysql"]  # Optional: filter by technology
    depth: standard  # quick, standard, or thorough
    tags: ["custom"]
    payloads:
      - value: "payload here"
        description: "What this payload does"
    detection:
      - type: string
        value: "expected response"
        description: "How to detect success"
```

## Vulnerability Types

Common vuln_type values: sqli, xss_reflected, xss_stored, xss_dom, ssrf, ssti,
idor, broken_auth, sensitive_data, csrf, xxe, lfi, rfi, command_injection,
deserialization, open_redirect
