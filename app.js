const express = require('express');
require('express-async-errors');
const cors = require('cors');
const cookieParser = require('cookie-parser');

// middleware
const handlerError = require('./middleware/handler-error');
const loggerRequest = require('./middleware/logger-request');
const extractorUser = require('./middleware/extractor-user');

// routes
const routerBlogs = require('./features/blogs/blogs.controller');
const routerAccounts = require('./features/accounts/account.controller');

const app = express();

app.use(cors());
app.use(express.static('build'));
app.use(express.json());
app.use(cookieParser());
app.use(loggerRequest);

app.use('/accounts', routerAccounts);
app.use('/blogs', extractorUser, routerBlogs);

app.use(handlerError);

module.exports = app;
