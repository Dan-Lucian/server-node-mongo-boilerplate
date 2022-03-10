const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const db = require('../../utils/db');
const role = require('../../utils/role');

const password = '12345678';
const passwordHash = bcrypt.hashSync(password, 10);

const accountRegistration = {
  userName: 'adam',
  firstName: 'Adam',
  lastName: 'Black',
  email: 'test@mail.com',
  password: '12345678',
  passwordConfirm: '12345678',
};

const accountOne = {
  _id: mongoose.Types.ObjectId(),
  userName: 'userName 1',
  firstName: 'firstName 1',
  lastName: 'lastName 1',
  verified: Date.now(),
  email: 'test1@mail.com',
  passwordHash,
  role: role.User,
  resetToken: {
    token: 'reset-token-one',
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
  },
};

const accountTwo = {
  _id: mongoose.Types.ObjectId(),
  userName: 'userName 2',
  firstName: 'firstName 2',
  lastName: 'lastName 2',
  verified: Date.now(),
  email: 'test2@mail.com',
  passwordHash,
  role: role.User,
  resetToken: {
    token: 'reset-token-two',
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
  },
};

const accountTokenResetExpired = {
  ...accountTwo,
  _id: mongoose.Types.ObjectId(),
  email: 'test-expired@mail.com',
  userName: 'userName expired',
  resetToken: {
    resetToken: {
      token: 'reset-token-expired',
      expires: Date.now() - 10,
    },
  },
};

const accountAdmin = {
  _id: mongoose.Types.ObjectId(),
  userName: 'userName admin',
  firstName: 'firstName admin',
  lastName: 'lastName admin',
  verified: Date.now(),
  email: 'test-admin@mail.com',
  passwordHash,
  role: role.Admin,
  resetToken: {
    token: 'reset-token-admin',
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
  },
};

const insertAccounts = async (accounts) => {
  await db.Account.insertMany(
    accounts.map((account) => ({ ...account, passwordHash }))
  );
};

module.exports = {
  accountOne,
  accountTwo,
  accountTokenResetExpired,
  accountAdmin,
  insertAccounts,
  accountRegistration,
};
