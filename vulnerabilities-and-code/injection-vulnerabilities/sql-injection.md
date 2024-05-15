# SQL Injection

### Concept

SQL Injection is a type of web application vulnerability that allows attackers to interfere with the queries made by the application to the database. It occurs when user input is incorrectly filtered or sanitized before being included in an SQL query. Attackers can manipulate the input to modify the query's structure and execute unintended commands or access sensitive data.

### Vulnerable Scenario

Suppose a web application uses user input to construct an SQL query for user authentication. The application directly concatenates the user input into the query string without proper sanitization.

#### Example Code (Vulnerable)

```python
username = request.form['username']
password = request.form['password']

query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
result = database.execute(query)

if result:
    # Authentication successful
    # ...
else:
    # Authentication failed
    # ...
```

### Explanation

In this example, the user input for `username` and `password` is directly concatenated into the SQL query string. If an attacker provides malicious input such as `' OR 1=1--` as the username, the resulting query becomes:

```sql
SELECT * FROM users WHERE username='' OR 1=1--' AND password=''
```

The `--` in the input acts as a comment, effectively nullifying the password check. The `OR 1=1` condition always evaluates to true, making the query return all rows from the `users` table. This allows the attacker to bypass the authentication mechanism and gain unauthorized access.

### Prevention

To prevent SQL Injection, consider the following measures:

1. Use parameterized queries or prepared statements instead of string concatenation to construct SQL queries. This ensures that user input is treated as data rather than executable code.
2. Validate and sanitize user input before using it in SQL queries. Implement strict input validation and filtering mechanisms to remove or escape special characters and SQL keywords.
3. Use appropriate database access controls and limit the privileges of the application's database user account to the minimum necessary.
4. Implement least privilege principles, ensuring that the application only has access to the required database tables and operations.

#### Example Code (Secure)

```python
username = request.form['username']
password = request.form['password']

query = "SELECT * FROM users WHERE username=? AND password=?"
result = database.execute(query, (username, password))

if result:
    # Authentication successful
    # ...
else:
    # Authentication failed
    # ...
```

In the secure example, parameterized queries are used to separate the user input from the SQL query structure. The placeholders `?` are used to represent the input values, and the actual values are passed as arguments to the `execute` method. This approach prevents the user input from being interpreted as SQL code, effectively mitigating SQL Injection.

### Conclusion

SQL Injection is a serious vulnerability that can lead to unauthorized access, data manipulation, and data exposure. It is crucial for developers to understand and mitigate this risk by implementing proper input validation, using parameterized queries, and following the principle of least privilege. By adopting secure coding practices and regularly testing for SQL Injection vulnerabilities, developers can protect their applications and safeguard sensitive data.



#### Semgrep Rule

This Semgrep rule can be used as a starting point to potentially identify this type of vulnerability.

```yaml
rules:
  - id: sql-injection
    patterns:
      - pattern: $DB.execute("SELECT ... WHERE $COLUMN = '" + $VALUE + "' ...")
    message: "Potential SQL Injection vulnerability. Use parameterized queries instead of string concatenation."
    languages:
      - python
    severity: ERROR
```
