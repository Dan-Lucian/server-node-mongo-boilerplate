/* eslint-disable prefer-destructuring */
require('dotenv').config();

const PORT = process.env.PORT;

const NODE_ENV = process.env.NODE_ENV;

const MONGODB_URI =
  NODE_ENV === 'test' || NODE_ENV === 'development'
    ? process.env.TEST_MONGODB_URI
    : process.env.MONGODB_URI;

const SECRET =
  NODE_ENV === 'test' || NODE_ENV === 'development'
    ? process.env.TEST_SECRET
    : process.env.SECRET;

module.exports = { PORT, MONGODB_URI, SECRET, NODE_ENV };
