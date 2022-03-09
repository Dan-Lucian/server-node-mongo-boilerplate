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
};

const insertAccounts = async (accounts) => {
  await db.Account.insertMany(
    accounts.map((account) => ({ ...account, passwordHash }))
  );
};

module.exports = {
  accountOne,
  accountTwo,
  accountAdmin,
  insertAccounts,
  accountRegistration,
};
