# Chapter 5: Error Handling & Validation

## TIER 2: Production-Ready

With proper error handling, your app is ready for real users!

---

## What You Will Learn

1. Standardized error response format
2. Input validation with helpful messages
3. HTTP status codes and when to use each
4. Global error handlers
5. Database rollback on errors

---

## Why Error Handling Matters

| Without | With |
|---------|------|
| Confusing stack traces | Clear error messages |
| Security info leaks | Generic messages to users |
| Hard to debug | Errors logged server-side |
| Bad UX | Helpful feedback |

---

## Standardized Response Format

### Error Response
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

### Success Response
```json
{
    "success": true,
    "message": "Registration successful!",
    "data": { ... }
}
```

---

## HTTP Status Codes

| Code | Name | When to Use |
|------|------|-------------|
| 200 | OK | Success (GET, PUT) |
| 201 | Created | Resource created (POST) |
| 400 | Bad Request | Invalid input |
| 401 | Unauthorized | Not logged in / bad token |
| 403 | Forbidden | Logged in but no permission |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | Already exists (duplicate) |
| 500 | Server Error | Our fault |

---

## Error Codes

| Code | Meaning |
|------|---------|
| VALIDATION_ERROR | Input validation failed |
| AUTH_ERROR | Authentication failed |
| TOKEN_EXPIRED | JWT token expired |
| TOKEN_INVALID | JWT token invalid |
| NOT_FOUND | Resource not found |
| ALREADY_EXISTS | Duplicate resource |
| SERVER_ERROR | Internal error |

---

## Input Validation

```python
def validate_registration(email, password):
    if not email:
        return False, error_response('VALIDATION_ERROR', 'Email is required', 'email')

    if not is_valid_email(email):
        return False, error_response('VALIDATION_ERROR', 'Invalid email format', 'email')

    if len(password) < 6:
        return False, error_response('VALIDATION_ERROR', 'Password too short', 'password')

    return True, None
```

---

## Database Rollback

```python
try:
    db.session.add(new_user)
    db.session.commit()
except Exception as e:
    db.session.rollback()  # Undo partial changes!
    return error_response('SERVER_ERROR', 'Operation failed')
```

---

## Global Error Handlers

```python
@app.errorhandler(404)
def not_found(error):
    return error_response('NOT_FOUND', 'Resource not found', status_code=404)

@app.errorhandler(Exception)
def handle_exception(error):
    app.logger.error(f'Error: {error}')  # Log for debugging
    return error_response('SERVER_ERROR', 'Something went wrong', status_code=500)
```

---

## How to Run

```bash
cd chapter-5/backend
python app.py
```

Test errors: `GET /test-error/validation`

---

## Self-Study Questions

1. Why use error codes like "VALIDATION_ERROR" instead of just messages?
2. When should you use 400 vs 401 vs 403?
3. Why rollback database on errors?
4. Why log errors but show generic messages to users?

---

## Next Chapter

[Chapter 6: Email Verification](../chapter-6/README.md)
