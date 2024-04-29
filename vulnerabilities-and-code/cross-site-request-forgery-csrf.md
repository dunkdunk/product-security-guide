# Cross-Site Request Forgery (CSRF)

### Concept

Cross-Site Request Forgery (CSRF) is a vulnerability that occurs when a web application allows attackers to trick authenticated users into performing unintended actions on the application. The attacker crafts a malicious request and induces the victim to send it to the vulnerable application, causing the application to perform actions on behalf of the victim without their knowledge or consent.

### Vulnerable Scenario

Consider a web application that relies solely on session cookies for authentication and does not implement any additional CSRF protection measures. The application performs sensitive actions, such as changing user settings or making financial transactions, based on the received requests.

#### Example Code (Vulnerable)

```python
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = 'secret-key'

@app.route('/transfer', methods=['POST'])
def transfer_funds():
    if 'user_id' in session:
        amount = request.form['amount']
        recipient = request.form['recipient']
        # Perform the fund transfer
        # ...
        return "Funds transferred successfully"
    else:
        return "Unauthorized", 401
```

### Explanation

In this example, the `/transfer` route handles POST requests to transfer funds. The application checks if the `user_id` is present in the session, indicating that the user is authenticated. If the user is authenticated, the application retrieves the `amount` and `recipient` from the request form data and performs the fund transfer.

An attacker can exploit this vulnerability by creating a malicious HTML form that submits a request to the `/transfer` endpoint with the desired `amount` and `recipient` parameters. The attacker then tricks the victim into visiting a web page containing the malicious form or clicking a link that automatically submits the form.

```html
<form action="http://example.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="recipient" value="attacker@example.com">
  <input type="submit" value="Click me!">
</form>
```

When the victim clicks the submit button or visits the malicious page while authenticated, the form is submitted to the vulnerable application. Since the application relies solely on session cookies for authentication, it considers the request as legitimate and performs the fund transfer on behalf of the victim.

### Prevention

To prevent Cross-Site Request Forgery (CSRF), consider the following measures:

1. Implement CSRF tokens: Generate a unique, unpredictable token for each user session and include it as a hidden field in every form or as a parameter in every request. Verify the presence and validity of the CSRF token on the server-side before processing the request.
2. Use the SameSite attribute for cookies: Set the SameSite attribute of session cookies to 'Strict' or 'Lax' to prevent cookies from being sent with cross-site requests.
3. Implement proper HTTP methods: Use the appropriate HTTP methods for different actions (e.g., GET for safe actions, POST for state-changing actions) and validate the expected HTTP method on the server-side.
4. Implement additional authentication mechanisms: Use multi-factor authentication or re-authentication for sensitive actions to ensure that the user explicitly confirms the action.
5. Validate and sanitize user input: Ensure that user input is properly validated and sanitized to prevent injection attacks or malicious data submission.

#### Example Code (Secure)

```python
from flask import Flask, request, session, render_template
import secrets

app = Flask(__name__)
app.secret_key = 'secret-key'

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

@app.route('/transfer', methods=['POST'])
def transfer_funds():
    if 'user_id' in session:
        csrf_token = request.form.get('csrf_token')
        if csrf_token == session.get('csrf_token'):
            amount = request.form['amount']
            recipient = request.form['recipient']
            # Perform the fund transfer
            # ...
            return "Funds transferred successfully"
        else:
            return "Invalid CSRF token", 403
    else:
        return "Unauthorized", 401

@app.route('/transfer', methods=['GET'])
def transfer_form():
    csrf_token = generate_csrf_token()
    return render_template('transfer.html', csrf_token=csrf_token)
```

In the secure example, the application generates a unique CSRF token for each user session using the `secrets` module. The CSRF token is stored in the session and included as a hidden field in the transfer form template (`transfer.html`).

When the `/transfer` route receives a POST request, it checks the presence and validity of the CSRF token by comparing it with the token stored in the session. If the tokens match, the fund transfer is performed. Otherwise, an "Invalid CSRF token" error is returned.

By using CSRF tokens and validating them on the server-side, the application prevents CSRF attacks and ensures that only legitimate requests from the same origin are processed.

### Conclusion

Cross-Site Request Forgery (CSRF) is a serious vulnerability that allows attackers to trick authenticated users into performing unintended actions on a web application. To mitigate CSRF, it is essential to implement CSRF tokens, use the SameSite attribute for cookies, validate HTTP methods, implement additional authentication mechanisms, and properly validate and sanitize user input. Developers should follow best practices and use secure coding techniques to protect against CSRF attacks and ensure the integrity of user actions within the application.

#### **Semgrep Rule**

This Semgrep rule can be used as a starting point to potentially identify this type of vulnerability.

```yaml
rules:
  - id: csrf-vulnerability
    patterns:
      - pattern: |
          @app.route(..., methods=['POST'])
          def $HANDLER(...):
            ...
            $SENSITIVE_ACTION
            ...
      - pattern-not: |
          @app.route(..., methods=['POST'])
          def $HANDLER(...):
            ...
            if <... CSRF_TOKEN_VALIDATION ...>:
              ...
              $SENSITIVE_ACTION
              ...
    message: "Potential Cross-Site Request Forgery (CSRF) vulnerability. Ensure CSRF tokens are properly validated."
    languages:
      - python
    severity: ERROR
```
