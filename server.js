const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const { UserStore } = require('./store');
const { RateLimiter } = require('./rate-limit');
const { hashPassword, verifyPassword, validPassword, token, sha256 } = require('./security');

const app = express();
const store = new UserStore(path.join(__dirname, 'instance'));
const sessions = new Map();
const resetTokens = new Map();
const limiter = new RateLimiter();

app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store'
  }); next();
});

function normalizeEmail(value) { return String(value || '').trim().toLowerCase(); }
function validEmail(email) { return /^[^\s@]{1,64}@[^\s@]{1,190}$/.test(email); }
function cookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').filter(Boolean).map(item => {
    const index = item.indexOf('='); return [item.slice(0, index).trim(), decodeURIComponent(item.slice(index + 1))];
  }));
}
function currentSession(req) {
  const session = sessions.get(cookies(req).sid);
  if (!session || session.expiresAt < Date.now()) return null;
  return session;
}
function requireAuth(req, res, next) {
  const session = currentSession(req);
  if (!session) return res.status(401).json({ error: 'Authentication required.' });
  req.auth = session; next();
}
function requireCsrf(req, res, next) {
  if (req.auth.csrf !== req.get('X-CSRF-Token')) return res.status(403).json({ error: 'Invalid CSRF token.' });
  next();
}
function requireAdmin(req, res, next) {
  const user = store.byId(req.auth.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Administrator access required.' });
  next();
}

app.post('/api/register', (req, res) => {
  const email = normalizeEmail(req.body.email); const password = req.body.password;
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Use 12+ characters with uppercase, lowercase, number, and symbol.' });
  if (store.byEmail(email)) return res.status(409).json({ error: 'Account already exists.' });
  const role = store.count() === 0 ? 'admin' : 'user';
  store.insert({ id: crypto.randomUUID(), email, passwordHash: hashPassword(password), role, createdAt: new Date().toISOString() });
  res.status(201).json({ message: `Account created with ${role} role.` });
});

app.post('/api/login', (req, res) => {
  const email = normalizeEmail(req.body.email); const key = `${req.ip}:${email}`;
  const check = limiter.check(key);
  if (!check.allowed) return res.status(429).json({ error: `Too many attempts. Try again in ${check.retryAfter} seconds.` });
  const user = store.byEmail(email);
  if (!user || !verifyPassword(req.body.password || '', user.passwordHash)) {
    limiter.fail(key); return res.status(401).json({ error: 'Invalid email or password.' });
  }
  limiter.clear(key);
  const sid = token(); const csrf = token();
  sessions.set(sid, { userId: user.id, csrf, expiresAt: Date.now() + 30 * 60 * 1000 });
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800`);
  res.json({ email: user.email, role: user.role, csrf });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = store.byId(req.auth.userId); res.json({ email: user.email, role: user.role, csrf: req.auth.csrf });
});

app.post('/api/logout', requireAuth, requireCsrf, (req, res) => {
  sessions.delete(cookies(req).sid); res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ message: 'Logged out.' });
});

app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  res.json({ users: store.all().map(({ id, email, role, createdAt }) => ({ id, email, role, createdAt })) });
});

app.post('/api/forgot-password', (req, res) => {
  const email = normalizeEmail(req.body.email); const user = store.byEmail(email);
  let demoToken = null;
  if (user) {
    const raw = token(); demoToken = raw;
    resetTokens.set(sha256(raw), { userId: user.id, expiresAt: Date.now() + 10 * 60 * 1000 });
  }
  res.json({ message: 'If the account exists, a reset link has been generated.', demoToken });
});

app.post('/api/reset-password', (req, res) => {
  const key = sha256(String(req.body.token || '')); const record = resetTokens.get(key);
  if (!record || record.expiresAt < Date.now()) return res.status(400).json({ error: 'Reset token is invalid or expired.' });
  if (!validPassword(req.body.password)) return res.status(400).json({ error: 'Use 12+ characters with uppercase, lowercase, number, and symbol.' });
  store.update(record.userId, { passwordHash: hashPassword(req.body.password) }); resetTokens.delete(key);
  for (const [sid, session] of sessions) if (session.userId === record.userId) sessions.delete(sid);
  res.json({ message: 'Password updated. Existing sessions were revoked.' });
});

if (require.main === module) app.listen(3000, '127.0.0.1', () => console.log('ShieldAuth running at http://127.0.0.1:3000'));
module.exports = { app };
