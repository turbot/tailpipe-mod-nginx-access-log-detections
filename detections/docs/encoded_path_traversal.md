## Overview

Detect when a web server received requests with URL-encoded or otherwise obfuscated path traversal patterns. This detection focuses on identifying path traversal attempts that use various encoding methods to evade basic security controls, making it effective at catching more sophisticated attacks.

Attackers use encoding techniques to bypass simple pattern matching and security filters when attempting path traversal attacks. Common encoding methods include URL encoding (percent encoding) where characters are replaced with their hexadecimal ASCII values (e.g., `../` becomes `%2e%2e%2f`), double encoding where already encoded values are encoded again (e.g., `%2e` becomes `%252e`), Unicode/UTF-8 encoding using the `%u` notation (e.g., `../` becomes `%u002e%u002e%u002f`), and backslash variants particularly targeting Windows systems (e.g., `../` becomes `..%5c`). These encoding techniques are often combined with other evasion methods like path normalization tricks and null byte injection.

When this detection triggers, security teams should verify if the access attempt was successful, analyze what files the attacker was attempting to access, implement a web application firewall with rules to block encoded path traversal, use proper input validation with allowlists rather than denylists, apply the principle of least privilege for web server file access, patch and update web applications and frameworks, and implement proper file access controls. False positives may occur with applications that use encoded characters in URLs for legitimate purposes, language or internationalization features that use Unicode characters, frameworks that use URL encoding for special characters, and content management systems with complex URL structures.

**References**:
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP: Testing for Path Traversal](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
- [MITRE ATT&CK: File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/) 