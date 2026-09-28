class RateLimiter {
  constructor(limit = 5, windowMs = 10 * 60 * 1000, lockMs = 60 * 1000, clock = Date.now) {
    this.limit = limit; this.windowMs = windowMs; this.lockMs = lockMs; this.clock = clock;
    this.attempts = new Map(); this.locks = new Map();
  }
  check(key) {
    const now = this.clock(); const lockedUntil = this.locks.get(key) || 0;
    if (lockedUntil > now) return { allowed: false, retryAfter: Math.ceil((lockedUntil - now) / 1000) };
    this.locks.delete(key);
    const recent = (this.attempts.get(key) || []).filter(time => time > now - this.windowMs);
    this.attempts.set(key, recent);
    return { allowed: true, retryAfter: 0 };
  }
  fail(key) {
    const recent = this.check(key).allowed ? this.attempts.get(key) || [] : [];
    recent.push(this.clock()); this.attempts.set(key, recent);
    if (recent.length >= this.limit) { this.attempts.delete(key); this.locks.set(key, this.clock() + this.lockMs); }
  }
  clear(key) { this.attempts.delete(key); this.locks.delete(key); }
}
module.exports = { RateLimiter };
