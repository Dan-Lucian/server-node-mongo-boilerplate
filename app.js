const express = require('express');
require('express-async-errors');
const cors = require('cors');
const middleware = require('./utils/middleware');

// routes
const routerBlogs = require('./features/blogs/blogs.controller');
const routerAccounts = require('./features/accounts/account.controller');

const app = express();

app.use(cors());
app.use(express.static('build'));
app.use(express.json());
app.use(middleware.loggerRequest);

app.use('/accounts', routerAccounts);
app.use('/blogs', middleware.extractorUser, routerBlogs);

app.use(middleware.endpointUknown);
app.use(middleware.handlerError);

module.exports = app;
