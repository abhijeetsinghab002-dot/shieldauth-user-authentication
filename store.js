const fs = require('node:fs');
const path = require('node:path');

class UserStore {
  constructor(directory) {
    fs.mkdirSync(directory, { recursive: true });
    this.file = path.join(directory, 'users.json');
    if (!fs.existsSync(this.file)) fs.writeFileSync(this.file, '[]', { mode: 0o600 });
  }

  all() { return JSON.parse(fs.readFileSync(this.file, 'utf8')); }
  save(users) {
    const temporary = `${this.file}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(users, null, 2), { mode: 0o600 });
    fs.renameSync(temporary, this.file);
  }
  byEmail(email) { return this.all().find(user => user.email === email); }
  byId(id) { return this.all().find(user => user.id === id); }
  insert(user) { const users = this.all(); users.push(user); this.save(users); }
  update(id, changes) {
    const users = this.all();
    const index = users.findIndex(user => user.id === id);
    if (index < 0) return false;
    users[index] = { ...users[index], ...changes };
    this.save(users);
    return true;
  }
  count() { return this.all().length; }
}

module.exports = { UserStore };
