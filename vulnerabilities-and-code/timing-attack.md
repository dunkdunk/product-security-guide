# Timing Attack

### Concept

A timing attack is a type of side-channel attack where an attacker exploits variations in the time taken by a system to process different inputs. By measuring and analyzing the response times, an attacker can infer sensitive information, such as the presence of certain data, the length of a password, or the correctness of a comparison operation.

Timing attacks are particularly relevant in scenarios where the application's response time depends on the processing of sensitive data, such as comparing passwords or cryptographic operations.

### Vulnerable Scenario

Consider a web application that implements a password verification function. The function compares the user-supplied password with the stored password character by character and returns an error message as soon as a mismatch is found.

#### Example Code (Vulnerable)

```python
def verify_password(user_password, stored_password):
    if len(user_password) != len(stored_password):
        return False

    for i in range(len(user_password)):
        if user_password[i] != stored_password[i]:
            return False

    return True
```

### Explanation

In this example, the `verify_password` function compares the user-supplied password (`user_password`) with the stored password (`stored_password`) character by character. If the lengths of the passwords don't match, the function immediately returns `False`. Otherwise, it iterates over each character of the passwords and returns `False` as soon as a mismatch is found.

An attacker can exploit this timing difference to determine the correct characters of the stored password. By measuring the response times for different input passwords, the attacker can infer which characters are correct and in which positions. The longer it takes for the function to return `False`, the more characters of the user-supplied password match the stored password.

For example, let's say the stored password is `"secret"`. The attacker can try different input passwords and observe the response times:

* Input: `"a"` - Response time: 10ms
* Input: `"s"` - Response time: 20ms
* Input: `"sa"` - Response time: 30ms
* Input: `"sb"` - Response time: 20ms

Based on the response times, the attacker can deduce that the first character of the stored password is `"s"` because it takes longer to return `False` compared to other characters.

By repeatedly trying different characters and measuring the response times, the attacker can gradually guess the entire stored password.

### Prevention

To prevent timing attacks, consider the following measures:

1. Use constant-time comparison functions: Implement comparison functions that always take the same amount of time, regardless of the input. This can be achieved by comparing all characters of the input and the stored value, even if a mismatch is found early.
2. Add random delays: Introduce random delays in the processing of sensitive operations to make it harder for an attacker to distinguish between different inputs based on timing.
3. Use secure cryptographic functions: Utilize secure cryptographic functions, such as hash functions or encryption algorithms, that are designed to be resilient against timing attacks.
4. Limit the granularity of error messages: Avoid providing detailed error messages that could leak information about the correctness of individual characters or the progress of the comparison operation.

#### Example Code (Secure)

```python
import hmac
import secrets

def verify_password(user_password, stored_password_hash):
    # Generate a random delay to obscure timing differences
    delay = secrets.randbelow(100)
    time.sleep(delay / 1000)

    # Use a constant-time comparison function
    user_password_hash = hmac.new(key, user_password.encode(), 'sha256').digest()
    return hmac.compare_digest(user_password_hash, stored_password_hash)
```

In the secure example, several improvements have been made:

* A random delay is introduced using `secrets.randbelow()` to obscure timing differences between different inputs.
* The `hmac` module is used to compute a hash of the user-supplied password using a secure key.
* The `hmac.compare_digest()` function is used to perform a constant-time comparison between the computed hash and the stored password hash.

By using a constant-time comparison function and adding random delays, the timing differences between different inputs are minimized, making it much harder for an attacker to infer sensitive information based on response times.

### Conclusion

Timing attacks exploit variations in the time taken by a system to process different inputs, allowing attackers to infer sensitive information. To prevent timing attacks, it is important to use constant-time comparison functions, add random delays, utilize secure cryptographic functions, and limit the granularity of error messages. Developers should be aware of the potential risks associated with timing differences and implement secure coding practices to mitigate the risk of timing attacks.

#### **Semgrep Rule**

Detecting timing attacks with static analysis tools like Semgrep can be challenging, as they often rely on dynamic behavior and measuring response times. However, you can use Semgrep to identify potential issues related to insecure comparison functions or lack of constant-time operations.

```yaml
rules:
  - id: insecure-comparison
    patterns:
      - pattern: |
          for $I in range(len($PASSWORD)):
              if $PASSWORD[$I] != $STORED_PASSWORD[$I]:
                  return False
    message: "Potential timing attack vulnerability. Use a constant-time comparison function for sensitive operations."
    languages:
      - python
    severity: WARNING
```

This Semgrep rule identifies code patterns where a password comparison is performed character by character using a loop, which can introduce timing differences. It suggests using a constant-time comparison function instead.

Note that this rule is a starting point and may generate false positives or false negatives. It's important to manually review the code and consider the specific context and requirements of your application.
