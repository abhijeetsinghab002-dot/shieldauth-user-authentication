# ShieldAuth — User Authentication System

A local educational Node.js/Express authentication project featuring signup, sign-in, salted scrypt password hashing, secure random server-side sessions, CSRF protection, login lockout, password reset, session revocation, and role-based access control.

## Windows setup

Open the extracted folder, click File Explorer's address bar, type `cmd`, and press Enter. Run:

```bat
npm install
npm test
npm start
```

Open `http://127.0.0.1:3000`.

The first registered account becomes the local demo administrator. Later accounts receive the `user` role.

Use a demonstration password such as `DemoPassword1!`. Do not reuse a real password.

## Security design

- Passwords use Node's scrypt KDF with a unique random salt.
- Password comparisons use constant-time verification.
- Sessions are random, server-side, expire after 30 minutes, and use HttpOnly/SameSite cookies.
- State-changing authenticated requests require a CSRF token.
- Five failed login attempts trigger a temporary lockout.
- Reset tokens are random, stored only as SHA-256 hashes, expire after 10 minutes, and are single-use.
- Password reset revokes existing sessions.
- Admin routes enforce server-side role checks.
- User data under `instance/` is ignored by Git.

This is a local learning project, not a production identity provider. Production deployment additionally needs HTTPS, a durable session store, verified email delivery, security monitoring, secrets management, and operational controls.
