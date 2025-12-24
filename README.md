# Secure Coding Patterns

A hands-on training guide for security teams and developers to learn application security through practical code examples.

## What This Guide Covers

This training material teaches **26 common web application vulnerabilities** using real-world code examples. Each vulnerability is presented through a side-by-side comparison of vulnerable and secure code, making it easy to understand both the problem and the solution.

## Learning Approach

**See the Vulnerability** → Every guide starts with a vulnerable code example that contains a real security flaw

**Understand the Exploit** → Learn how attackers exploit the vulnerability to compromise applications or access sensitive data

**Apply the Fix** → Step-by-step instructions show how to remediate the vulnerability with secure coding practices

**Detect It Early** → Each vulnerability includes a [Semgrep](https://semgrep.dev/) rule template to integrate into your SAST scanning and CI/CD pipelines

## Who This Is For

- **Security teams** training developers on secure coding practices
- **Application security engineers** learning to identify and remediate vulnerabilities
- **Development teams** improving their security knowledge through practical examples
- **Security champions** teaching peers about common web security issues

## What's Included

26 vulnerabilities organized into 5 categories:

- **Injection Vulnerabilities** (6) - SQL, SSTI, XPath, XXE, Request Smuggling, Deserialization
- **Input-based Vulnerabilities** (3) - XSS, CSP Misconfiguration, HTTP Parameter Pollution
- **Origin-related Vulnerabilities** (3) - CSRF, SSRF, CORS Misconfiguration
- **Access-related Vulnerabilities** (6) - IDOR, Auth Code Interception, Session Hijacking, TLS Issues, JWT Vulnerabilities
- **Logic & Timing Vulnerabilities** (3) - Business Logic Flaws, Type Juggling, Timing Attacks

## Note

This guide focuses on practical code-level vulnerabilities. It is not exhaustive but covers the most common web application security issues encountered in modern development.
