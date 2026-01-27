# Part 8: Error Handling

## What You Will Learn

1. Create consistent error responses
2. Handle different types of errors
3. Display errors nicely on frontend
4. Input validation
5. Global error handler

---

## Why Error Handling Matters

Without proper error handling:
- Users see confusing error messages
- Hard to debug problems
- Security info might leak
- Bad user experience

With proper error handling:
- Clear, helpful error messages
- Easy to debug
- Secure (no sensitive info leaked)
- Good user experience

---

## Error Response Format

Use consistent format for all errors:

```json
{
    "success": false,
    "error": {
        "code": "VALIDATION_ERROR",
        "message": "Email is required",
        "field": "email"
    }
}
```

### Error Codes

| Code | Meaning |
|------|---------|
| VALIDATION_ERROR | Input validation failed |
| AUTH_ERROR | Authentication failed |
| NOT_FOUND | Resource not found |
| ALREADY_EXISTS | Resource already exists |
| TOKEN_EXPIRED | JWT or reset token expired |
| TOKEN_INVALID | Invalid token |
| SERVER_ERROR | Internal server error |

---

## Backend Error Handling

### 1. Input Validation
```python
# Check required fields
if not email:
    return error_response('VALIDATION_ERROR', 'Email is required', 'email')
```

### 2. Try-Except Blocks
```python
try:
    # risky operation
    result = do_something()
except SpecificError as e:
    return error_response('SPECIFIC_ERROR', str(e))
except Exception as e:
    return error_response('SERVER_ERROR', 'Something went wrong')
```

### 3. Global Error Handler
```python
@app.errorhandler(Exception)
def handle_error(error):
    # Catch all uncaught errors
    return error_response('SERVER_ERROR', 'Internal server error')
```

---

## Frontend Error Handling

### 1. Try-Catch for API Calls
```javascript
try {
    const response = await fetch('/api/login', ...);
    const data = await response.json();

    if (!response.ok) {
        showError(data.error.message);
        return;
    }
    // success
} catch (error) {
    showError('Network error. Please try again.');
}
```

### 2. Form Validation
```javascript
function validateForm() {
    if (!email) {
        showError('Email is required');
        return false;
    }
    if (!isValidEmail(email)) {
        showError('Invalid email format');
        return false;
    }
    return true;
}
```

---

## Validation Rules

### Email
- Required
- Valid email format
- Max 120 characters

### Password
- Required
- Minimum 6 characters
- (Optional) Must contain number
- (Optional) Must contain special character

---

## Files in This Part

```
part-8/
├── backend/
│   ├── app.py              # Flask API with error handling
│   └── requirements.txt
├── frontend/
│   └── index.html          # Frontend with error display
└── README.md
```

---

## How to Run

```bash
cd part-8/backend
pip install -r requirements.txt
python app.py
```

Open `part-8/frontend/index.html` in browser.

---

## Testing Error Scenarios

Try these to see error handling:

| Test | Expected Error |
|------|----------------|
| Register with empty email | "Email is required" |
| Register with invalid email | "Invalid email format" |
| Register with existing email | "Email already exists" |
| Login with wrong password | "Invalid email or password" |
| Access protected route without token | "Token is missing" |
| Access with expired token | "Token has expired" |

---

## Security Note

**Never reveal internal errors to users!**

Bad:
```json
{
    "error": "SQL Error: column 'password' not found in table 'users'"
}
```

Good:
```json
{
    "error": {
        "code": "SERVER_ERROR",
        "message": "Something went wrong. Please try again."
    }
}
```

Log internal errors on server, show generic message to user.

---

## Test Your Understanding

1. Why use error codes like "VALIDATION_ERROR"?
2. Why shouldn't we show SQL errors to users?
3. What's the difference between validation error and server error?
4. How does frontend handle network errors?

---

## Next Part

[Part 9: Role-Based Access](../part-9/README.md)
