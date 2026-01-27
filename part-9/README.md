# Part 9: Role-Based Access Control

## What You Will Learn

1. Add roles to users (admin, user)
2. Protect routes by role
3. Create admin-only endpoints
4. Handle role in frontend

---

## What is Role-Based Access Control (RBAC)?

Different users have different permissions:

| Role | Can Access |
|------|------------|
| User | Own profile, basic features |
| Admin | Everything + admin panel, manage users |

---

## Database Change

Add `role` column to User:

```python
class User(db.Model):
    id = ...
    email = ...
    password = ...
    role = db.Column(db.String(20), default='user')  # NEW!
```

Possible roles:
- `user` - Regular user (default)
- `admin` - Administrator

---

## How Role Check Works

```
1. User logs in
2. JWT token contains user's role
3. User accesses admin route
4. Backend reads role from token
5. If admin: Allow access
6. If not admin: Return 403 Forbidden
```

---

## JWT Token with Role

```json
{
    "user_id": 1,
    "email": "admin@example.com",
    "role": "admin",
    "exp": 1234567890
}
```

---

## Decorators for Role Protection

```python
# Only logged-in users
@token_required
def any_user_route():
    pass

# Only admin users
@token_required
@admin_required
def admin_only_route():
    pass
```

---

## Files in This Part

```
part-9/
├── backend/
│   ├── app.py              # Flask API with RBAC
│   └── requirements.txt
├── frontend/
│   └── index.html          # Test role-based access
└── README.md
```

---

## How to Run

```bash
cd part-9/backend
pip install -r requirements.txt
python app.py
```

Open `part-9/frontend/index.html` in browser.

---

## API Endpoints

### Public Routes
| Method | Route | Description |
|--------|-------|-------------|
| POST | /register | Register user |
| POST | /login | Login |

### User Routes (any logged-in user)
| Method | Route | Description |
|--------|-------|-------------|
| GET | /profile | Get own profile |

### Admin Routes (admin only)
| Method | Route | Description |
|--------|-------|-------------|
| GET | /admin/users | Get all users |
| PUT | /admin/users/:id/role | Change user's role |
| DELETE | /admin/users/:id | Delete user |

---

## Creating Admin User

Option 1: Register and upgrade via API
```bash
# First register normally
# Then use admin endpoint to upgrade role
```

Option 2: Direct database
```python
# In Python shell
user = User.query.filter_by(email='admin@example.com').first()
user.role = 'admin'
db.session.commit()
```

Option 3: Use the `/make-admin` route (testing only)
```
POST /make-admin
{ "email": "admin@example.com", "secret": "admin-secret-key" }
```

---

## HTTP Status Codes

| Code | Meaning | When |
|------|---------|------|
| 200 | OK | Success |
| 401 | Unauthorized | Not logged in |
| 403 | Forbidden | Logged in but no permission |
| 404 | Not Found | Resource not found |

---

## Frontend Role Handling

```javascript
// After login, check role
const user = response.data.user;

if (user.role === 'admin') {
    // Show admin panel
    showAdminPanel();
} else {
    // Show regular user UI
    showUserPanel();
}
```

---

## Security Best Practices

1. **Always check role on backend** - Never trust frontend
2. **Use principle of least privilege** - Give minimum required access
3. **Log admin actions** - Keep audit trail
4. **Validate role changes** - Only super-admin can create admins

---

## Test Your Understanding

1. What's the difference between 401 and 403?
2. Why must we check roles on backend, not just frontend?
3. What role should new users get by default?
4. Can a regular user access admin routes?

---

## Next Part

[Part 10: Refresh Token & Logout](../part-10/README.md)
