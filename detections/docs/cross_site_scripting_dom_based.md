## Overview

The DOM-Based XSS Attack detection identifies potential Cross-Site Scripting (XSS) attacks that specifically target JavaScript Document Object Model (DOM) manipulation. Unlike traditional XSS attacks that focus on server-side vulnerabilities, DOM-based XSS exploits client-side JavaScript that dynamically modifies the page's DOM.

This detection examines both HTTP requests and User-Agent headers for JavaScript DOM manipulation methods and properties commonly used in DOM-based XSS attacks. It looks for patterns like `document.getElementById`, `document.querySelector`, `innerHTML`, `outerHTML`, and various document location properties that can be used to introduce malicious code into the page.

DOM-based XSS attacks are particularly dangerous because they often bypass traditional server-side XSS protections. The vulnerability occurs when client-side JavaScript code improperly handles data from untrusted sources (like URL parameters or form inputs) and uses it to modify the DOM without adequate sanitization. For example, an application might take a value from the URL and insert it into the page using `innerHTML`, allowing an attacker to inject malicious script.

These attacks typically target single-page applications, complex web interfaces, and sites with significant client-side functionality. By examining both request URIs and User-Agent headers, this detection can identify attackers who attempt to evade security controls by hiding their payloads in HTTP headers rather than request parameters.

This comprehensive approach helps security teams identify sophisticated DOM-based XSS attempts targeting their web applications, which might otherwise evade detection by traditional server-side security controls.

**References**:
- [OWASP DOM-Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2021: A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [MITRE ATT&CK: T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)