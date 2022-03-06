const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../utils/db');
const { SECRET } = require('../utils/config');

const routerLogin = express.Router();

routerLogin.post('/', async (request, response) => {
  const { username, password } = request.body;

  const user = await db.Account.findOne({ username });
  const isPasswordCorrect =
    user === null ? false : await bcrypt.compare(password, user.passwordHash);

  if (!(user && isPasswordCorrect)) {
    return response.status(401).json({ error: 'invalid username or password' });
  }

  const token = jwt.sign({ username, id: user._id }, SECRET);
  response.status(200).json({ token, username, name: user.name });
});

module.exports = routerLogin;
