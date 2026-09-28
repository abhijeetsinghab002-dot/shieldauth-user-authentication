const crypto = require('node:crypto');

const SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64, SCRYPT_OPTIONS);
  return `scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

function verifyPassword(password, stored) {
  try {
    const [algorithm, saltText, hashText] = stored.split('$');
    if (algorithm !== 'scrypt') return false;
    const salt = Buffer.from(saltText, 'base64url');
    const expected = Buffer.from(hashText, 'base64url');
    const actual = crypto.scryptSync(password, salt, expected.length, SCRYPT_OPTIONS);
    return crypto.timingSafeEqual(actual, expected);
  } catch (_) {
    return false;
  }
}

function validPassword(password) {
  return typeof password === 'string' && password.length >= 12 && password.length <= 128 &&
    /[a-z]/.test(password) && /[A-Z]/.test(password) && /\d/.test(password) && /[^A-Za-z0-9]/.test(password);
}

function token(bytes = 32) { return crypto.randomBytes(bytes).toString('base64url'); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

module.exports = { hashPassword, verifyPassword, validPassword, token, sha256 };
