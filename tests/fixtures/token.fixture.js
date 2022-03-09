const jwt = require('jsonwebtoken');
const db = require('../../utils/db');
const { accountOne, accountTwo, accountAdmin } = require('./account.fixture');
const { SECRET } = require('../../utils/config');

const tokenRefreshAccountOne = {
  account: accountOne._id,
  token: 'a_very_unique_token_account_one',
  expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // after a week
  createdByIp: 'some ip address',
};

const tokenRefreshAccountTwo = {
  account: accountTwo._id,
  token: 'a_very_unique_token_account_two',
  expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // after a week
  createdByIp: 'some ip address',
};

const tokenRefreshAccountAdmin = {
  account: accountAdmin._id,
  token: 'a_very_unique_token_account_admin',
  expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // after a week
  createdByIp: 'some ip address',
};

const tokenJwtAccountOne = jwt.sign(
  { sub: accountOne._id, id: accountOne._id },
  SECRET,
  {
    expiresIn: '15m',
  }
);

const tokenJwtAccountTwo = jwt.sign(
  { sub: accountTwo._id, id: accountTwo._id },
  SECRET,
  {
    expiresIn: '15m',
  }
);

const tokenJwtAccountAdmin = jwt.sign(
  { sub: accountAdmin._id, id: accountAdmin._id },
  SECRET,
  {
    expiresIn: '15m',
  }
);

const insertTokensRefresh = async (tokens) => {
  await db.TokenRefresh.insertMany(tokens.map((token) => token));
};

module.exports = {
  tokenRefreshAccountOne,
  tokenRefreshAccountTwo,
  tokenRefreshAccountAdmin,
  tokenJwtAccountOne,
  tokenJwtAccountTwo,
  tokenJwtAccountAdmin,
  insertTokensRefresh,
};
