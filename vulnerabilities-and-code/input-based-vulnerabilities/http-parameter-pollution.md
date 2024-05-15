# HTTP Parameter Pollution

### Concept

HTTP Parameter Pollution (HPP) is a vulnerability that occurs when a web application fails to properly handle multiple occurrences of the same parameter in an HTTP request. Attackers can exploit this vulnerability to manipulate the application's behavior, bypass input validation, or inject malicious data.

### Vulnerable Scenario

Consider a web application that accepts multiple parameters with the same name in an HTTP request. The application concatenates the values of these parameters into a single string without proper validation or sanitization.

#### Example Code (Vulnerable)

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    keywords = request.args.getlist('q')
    search_query = ' '.join(keywords)
    # Perform search operation with the concatenated search_query
    # ...
    return search_results
```

### Explanation

In this example, the `/search` route accepts multiple `q` parameters from the user via the query string. The `request.args.getlist('q')` function retrieves all the values associated with the `q` parameter as a list. The application then concatenates these values into a single string using `' '.join(keywords)` without any validation or sanitization.

An attacker can exploit this vulnerability by crafting a malicious request with multiple `q` parameters. For example:

```
http://example.com/search?q=python&q=security&q=; DROP TABLE users;--
```

In this request, the attacker injects multiple `q` parameters, including a malicious SQL injection payload (`; DROP TABLE users;--`). When the application concatenates the parameter values, the resulting `search_query` becomes:

```
python security ; DROP TABLE users;--
```

If this `search_query` is then used in an SQL query without proper escaping or parameterization, it can lead to SQL injection attacks, potentially allowing the attacker to manipulate the database, retrieve sensitive information, or perform unauthorized actions.

### Prevention

To prevent HTTP Parameter Pollution, consider the following measures:

1. Properly validate and sanitize user input before processing it. Ensure that input is treated as untrusted and is subject to strict validation and filtering mechanisms.
2. Use parameterized queries or prepared statements when constructing SQL queries to prevent SQL injection attacks.
3. Avoid concatenating user input directly into sensitive operations, such as SQL queries, file paths, or system commands.
4. Implement input validation and sanitization on the server-side to ensure that only expected and valid data is processed.
5. Consider using a whitelist approach for parameter names and values to restrict the allowed input to a predefined set of safe values.

#### Example Code (Secure)

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    keywords = request.args.getlist('q')
    sanitized_keywords = [sanitize_input(keyword) for keyword in keywords]
    search_query = ' '.join(sanitized_keywords)
    # Perform search operation with the sanitized search_query using parameterized queries
    # ...
    return search_results
```

In the secure example, each keyword obtained from the `q` parameter is individually sanitized using a `sanitize_input` function. This function should remove or escape any potentially malicious characters or syntax. The sanitized keywords are then concatenated into the `search_query` string.

When using the `search_query` in an SQL query or other sensitive operation, parameterized queries or prepared statements should be used to prevent SQL injection attacks.

### Conclusion

HTTP Parameter Pollution is a vulnerability that can lead to various security issues, such as SQL injection, input validation bypasses, and data manipulation. To mitigate HPP, it is essential to properly validate and sanitize user input, use parameterized queries or prepared statements for database operations, and implement strict input validation mechanisms. Developers should be cautious when handling multiple parameters with the same name and ensure that user input is treated as untrusted and subject to appropriate security measures.

#### **Semgrep Rule**

This Semgrep rule can be used as a starting point to potentially identify this type of vulnerability.

```yaml
rules:
  - id: http-parameter-pollution
    patterns:
      - pattern: request.args.getlist(...)
    message: "Potential HTTP Parameter Pollution vulnerability. Ensure proper validation and sanitization of input parameters."
    languages:
      - python
    severity: WARNING
```
