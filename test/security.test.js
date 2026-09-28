const test = require('node:test');
const assert = require('node:assert/strict');
const { hashPassword, verifyPassword, validPassword, token } = require('../security');
const { RateLimiter } = require('../rate-limit');

test('password hash verifies correct password',()=>{const hash=hashPassword('StrongPassword1!');assert.equal(verifyPassword('StrongPassword1!',hash),true);assert.equal(verifyPassword('wrong',hash),false)});
test('same password receives unique salts',()=>{assert.notEqual(hashPassword('StrongPassword1!'),hashPassword('StrongPassword1!'))});
test('password policy rejects weak password',()=>{assert.equal(validPassword('password'),false);assert.equal(validPassword('StrongPassword1!'),true)});
test('security tokens are random',()=>{assert.notEqual(token(),token())});
test('rate limiter locks after failures',()=>{let now=0;const limiter=new RateLimiter(2,1000,1000,()=>now);limiter.fail('x');limiter.fail('x');assert.equal(limiter.check('x').allowed,false);now=1001;assert.equal(limiter.check('x').allowed,true)});
