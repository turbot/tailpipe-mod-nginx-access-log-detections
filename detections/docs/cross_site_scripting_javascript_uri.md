## Overview

The XSS JavaScript URI Vector detection identifies Cross-Site Scripting (XSS) attacks that specifically leverage JavaScript URI schemes to execute malicious code. This attack vector is particularly dangerous as it can be used within various HTML attributes to trigger script execution.

This detection analyzes both HTTP requests and User-Agent headers for the presence of JavaScript URI schemes (`javascript:`) and their obfuscated variants. Attackers often use these URI schemes in attributes like `href`, `src`, `action`, and others to execute arbitrary JavaScript code when a user interacts with the element containing the malicious attribute.

JavaScript URI-based XSS attacks can be especially deceptive as they can be hidden in legitimate-looking links or redirects. When users click on links containing these URI schemes, the browser will execute the JavaScript code in the context of the current page, potentially leading to session hijacking, credential theft, or other malicious actions.

Attackers frequently employ obfuscation techniques to bypass security filters, including character splitting (e.g., `j%0Aa%0Avascript`), URL encoding, and various combinations of characters to spell out "javascript" in ways that may bypass simple pattern matching but are still interpreted by browsers as the JavaScript protocol.

By examining both request URIs and User-Agent headers, this detection can identify attackers who attempt to evade security controls by placing their payloads in HTTP headers rather than request parameters. This approach helps security teams identify potential vulnerability exploitation attempts targeting their web applications through this specific XSS vector.

**References**:
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2021: A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [MITRE ATT&CK: T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)