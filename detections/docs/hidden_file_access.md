## Overview

Detect attempts to access hidden files and directories in Nginx access logs. This detection identifies attempts to access files and directories that are typically hidden from normal web browsing, which might contain sensitive information or configuration details.

The detection focuses on identifying patterns that target hidden files and directories, including dot files, backup files, and configuration files that might be used to gather information about the Nginx web server or underlying system.

**References**:
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [MITRE ATT&CK: File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/) 