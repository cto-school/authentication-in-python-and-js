# Chapter 9: Role-Based Access Control (RBAC)

## TIER 3: Advanced

Control WHAT users can do based on their role.

---

## Authentication vs Authorization

| Concept | Question | HTTP Code |
|---------|----------|-----------|
| Authentication | WHO are you? | 401 Unauthorized |
| Authorization | WHAT can you do? | 403 Forbidden |

---

## RBAC Concept

Instead of checking permissions everywhere, assign users to ROLES:

```
USER role:
  - View own profile
  - Edit own profile

ADMIN role:
  - All USER permissions
  - View all users
  - Delete users
  - Change user roles
```

---

## Implementation

### 1. Add role to User model
```python
role = db.Column(db.String(20), default='user')
```

### 2. Include role in JWT token
```python
def create_token(user):
    return jwt.encode({
        'user_id': user.id,
        'role': user.role,  # Include role!
        ...
    }, SECRET_KEY)
```

### 3. Create @admin_required decorator
```python
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'admin':
            return jsonify({'message': 'Admin required'}), 403
        return f(*args, **kwargs)
    return decorated
```

### 4. Stack decorators
```python
@app.route('/admin/users')
@token_required      # First: Is user logged in?
@admin_required      # Second: Is user an admin?
def get_all_users():
    ...
```

---

## 401 vs 403

| Code | Name | Meaning |
|------|------|---------|
| 401 | Unauthorized | Not logged in / bad token |
| 403 | Forbidden | Logged in but no permission |

---

## Security Considerations

1. **Never register as admin** - Always 'user' role on register
2. **Prevent self-demotion** - Admin can't remove own admin role
3. **Prevent self-deletion** - Admin can't delete themselves

---

## How to Run

```bash
cd chapter-9/backend
python app.py
```

---

## Self-Study Questions

1. What's the difference between 401 and 403?
2. Why include role in the JWT token?
3. Why prevent self-demotion?
4. What is "principle of least privilege"?

---

## Next Chapter

[Chapter 10: Security Best Practices](../chapter-10/README.md) - The final chapter!
