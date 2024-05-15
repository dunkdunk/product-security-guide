# Insecure Direct Object References (IDOR)

### Concept

Insecure Direct Object References (IDOR) is a vulnerability that occurs when a web application uses user-supplied input to directly access objects or resources without proper authorization checks. Attackers can exploit this vulnerability to gain unauthorized access to sensitive data or perform actions on behalf of other users.

### Vulnerable Scenario

Consider a web application that uses user-supplied input, such as an ID or a filename, to directly retrieve records from a database or access files on the server. The application assumes that the user is authorized to access the requested resource without performing proper authorization checks.

#### Example Code (Vulnerable)

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    user = database.query(f"SELECT * FROM users WHERE id = {user_id}")
    return user.to_json()
```

### Explanation

In this example, the `/user` route accepts a `user_id` parameter from the user via the query string. The `user_id` is directly used in an SQL query to retrieve the corresponding user record from the database. The application assumes that the user making the request is authorized to access the requested user record.

An attacker can exploit this vulnerability by modifying the `id` parameter in the request to access user records they are not authorized to view. For example:

```
http://example.com/user?id=1234
```

By changing the `id` parameter to different values, the attacker can potentially retrieve sensitive information of other users, such as their personal details, account balances, or confidential data.

### Prevention

To prevent Insecure Direct Object References, consider the following measures:

1. Implement proper authorization checks to ensure that the user making the request has the necessary permissions to access the requested resource.
2. Avoid using user-supplied input directly to access sensitive resources. Instead, use an indirect reference map or a lookup table to map the user-supplied input to the actual resource.
3. Validate and sanitize user input to prevent injection attacks and ensure that only valid and authorized input is processed.
4. Use parameterized queries or prepared statements when constructing SQL queries to prevent SQL injection attacks.
5. Implement a robust access control mechanism that enforces authorization checks based on the user's roles, permissions, and ownership of resources.

#### Example Code (Secure)

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # Validate and sanitize the user_id
    sanitized_user_id = sanitize_input(user_id)
    
    # Check if the current user is authorized to access the requested user record
    if not is_authorized(current_user, sanitized_user_id):
        return "Unauthorized", 401
    
    user = database.query("SELECT * FROM users WHERE id = ?", sanitized_user_id)
    return user.to_json()
```

In the secure example, the `user_id` obtained from the user's request is first validated and sanitized using a `sanitize_input` function to prevent injection attacks. Then, an authorization check is performed using the `is_authorized` function to ensure that the current user has the necessary permissions to access the requested user record.

If the authorization check passes, the `user_id` is used in a parameterized SQL query to retrieve the user record from the database securely.

### Conclusion

Insecure Direct Object References is a vulnerability that can lead to unauthorized access to sensitive data and resources. To mitigate IDOR, it is crucial to implement proper authorization checks, use indirect reference maps, validate and sanitize user input, and employ parameterized queries or prepared statements for database operations. Developers should ensure that access control mechanisms are robust and enforce strict authorization checks based on user roles and permissions.

#### **Semgrep Rule**

This Semgrep rule can be used as a starting point to potentially identify this type of vulnerability.

```yaml
rules:
  - id: insecure-direct-object-reference
    patterns:
      - pattern: |
          $OBJECT = request.$PARAM
          ...
          query(f"... WHERE $COLUMN = {$OBJECT}")
    message: "Potential Insecure Direct Object Reference vulnerability. Ensure proper authorization checks are in place."
    languages:
      - python
    severity: ERROR
```
