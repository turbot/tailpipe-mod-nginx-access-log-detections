## Overview

Detect when a web server received requests with Local File Inclusion (LFI) attack patterns in the User-Agent or other headers. This specialized detection focuses on identifying path traversal and file inclusion attempts that specifically target HTTP headers rather than typical URL parameters or path components.

Header-based LFI attacks represent an advanced evasion technique where attackers place path traversal sequences and OS file paths in HTTP headers to bypass Web Application Firewalls (WAFs) and other security controls that focus on examining request URLs. Standard security controls often focus on URL parameters and paths while neglecting HTTP headers - many WAF configurations may not thoroughly inspect HTTP headers for attack patterns, header-based attacks can bypass security monitoring focused on request URLs, and headers are sometimes logged separately and may receive less security scrutiny.

This detection identifies multiple LFI techniques in HTTP headers, including basic path traversal with directory navigation sequences like `../` and `..\`, encoded path traversal with URL-encoded variants like `..%2f` and `%2e%2e%2f`, and OS file access attempts to access sensitive system files like `/etc/passwd`, `/etc/shadow`, and Windows configuration files. Web applications that process User-Agent headers without proper sanitization, logging infrastructure that stores header values in files whose paths are influenced by those values, and server-side includes or templates that might process and render header values are particularly at risk from these attack vectors.

**References**:
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP Testing Guide - Testing for Local File Inclusion](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion.html)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 