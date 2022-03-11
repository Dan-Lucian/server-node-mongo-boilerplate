const jwt = require('jsonwebtoken');
const db = require('../utils/db');
const { SECRET } = require('../config/env');

const extractorUser = async (request, response, next) => {
  const authorization = request.get('authorization');
  if (authorization && authorization.toLowerCase().startsWith('bearer ')) {
    const tokenDecoded = jwt.verify(authorization.substring(7), SECRET);
    if (tokenDecoded) {
      request.user = await db.Account.findById(tokenDecoded.id);
    }
  }

  next();
};

module.exports = extractorUser;
