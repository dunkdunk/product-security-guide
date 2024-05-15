# Server-Side Template Injection (SSTI)

### Concept

Server-Side Template Injection (SSTI) is a vulnerability that occurs when user input is insufficiently sanitized and passed to a template rendering engine. Attackers can exploit this vulnerability to inject malicious template code, which is then executed on the server, potentially leading to remote code execution or sensitive information disclosure.

### Vulnerable Scenario

Consider a web application that uses a server-side templating engine to render dynamic web pages. The application allows users to provide input that is directly passed to the template without proper sanitization.

#### Example Code (Vulnerable)

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greeting')
def greeting():
    name = request.args.get('name', '')
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)
```

### Explanation

In this example, the `greeting` route accepts a `name` parameter from the user via a query string. The user-provided `name` is directly inserted into the template string without any sanitization. The template is then rendered using `render_template_string`, which evaluates the template code on the server.

An attacker can exploit this vulnerability by providing malicious template code as the `name` parameter. For example, the attacker can inject the following payload:

```
{{ ''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['__builtins__']['__import__']('os').popen('cat /etc/passwd').read() }}
```

This payload uses the template engine's built-in functionality to traverse the object hierarchy, access the `os` module, and execute the `cat /etc/passwd` command to read sensitive system files. The result of the command execution is then rendered within the template, exposing sensitive information to the attacker.

### Prevention

To prevent Server-Side Template Injection, consider the following measures:

1. Avoid directly rendering user input in templates. Always sanitize and validate user input before passing it to the template engine.
2. Use safe template rendering functions provided by the framework or library you are using. These functions typically escape or sanitize user input automatically.
3. Limit the template execution environment by disabling unnecessary features and restricting access to sensitive modules or functions.
4. Implement strict input validation and filtering mechanisms to reject or sanitize user input that contains potentially dangerous characters or syntax.

#### Example Code (Secure)

```python
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/greeting')
def greeting():
    name = request.args.get('name', '')
    sanitized_name = sanitize_input(name)
    return render_template('greeting.html', name=sanitized_name)
```

```html
<!-- greeting.html -->
<h1>Hello, {{ name }}!</h1>
```

In the secure example, the user input is first sanitized using a `sanitize_input` function, which removes or escapes any potentially dangerous characters or syntax. The sanitized input is then passed to the `render_template` function, which renders a separate template file (`greeting.html`) instead of evaluating the template code directly.

By separating the user input from the template and using safe rendering functions, the risk of Server-Side Template Injection is greatly reduced.

### Conclusion

Server-Side Template Injection is a serious vulnerability that can lead to remote code execution and sensitive information disclosure. To protect against SSTI, it is crucial to properly sanitize and validate user input before passing it to template engines. Developers should use safe template rendering functions, limit the template execution environment, and implement strict input validation mechanisms. Regular security testing and keeping template engines and libraries up to date are also essential to maintain the security of web applications.



#### Semgrep Rule

This Semgrep rule can be used as a starting point to potentially identify this type of vulnerability.

```yaml
rules:
  - id: server-side-template-injection
    patterns:
      - pattern: render_template_string(...)
    message: "Potential Server-Side Template Injection vulnerability. Avoid rendering user input directly in templates."
    languages:
      - python
    severity: ERROR
```
