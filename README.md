
# RESTful express + mongo server boilerplate

A server boilerplate built upon express + mongoDB. The boilerplate comes with an authentication system based on jwt and refresh tokens fully covered by tests.

## Table of contents

- [Install](#install)
- [Features](#features)
- [API](#api)
- [Auth](#auth)
- [Tests](#tests)
- [Folder structure](#folder-structure)
- [Inspirations](#inspirations)
- [Final words](#final-words)

## Install
First step, copy the repository and run:

    npm i

Second step, you have to setup environment variables. Create a *.env* file at the top path of the repo and add the following variables each on a new line:

 - **`PORT=`** server port during develompent
 - **`MONGODB_URI=`** atlas uri to connect to
 - **`TEST_MONGODB_URI=`** atlas uri to connect to during tests
 - **`SECRET=`** secret key for the jsonwebtoken
 - **`TEST_SECRET=`** secret key for the jsonwebtoken duting tests

Third step, run the server in development mode which will be aided by [nodemon](https://nodemon.io/):

    npm run dev

## Features

- **Server base:** Node.js + [express](https://expressjs.com/)
- **Database:** Cloud MongoDB [Atlas](https://www.mongodb.com/atlas/database) + [mongoose](https://mongoosejs.com/)
- **Authorization and authentication:** built from scratch using [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken#readme) and refresh tokens
- **Emails:** with [nodemailer](https://nodemailer.com/about/) (disabled during tests)
- **Validation**: with [Joi](https://github.com/sideway/joi)
- **Environment variables:** with [dotenv](https://github.com/motdotla/dotenv#readme) and [cross-env](https://github.com/kentcdodds/cross-env)
- **Testing:** with [jest](https://jestjs.io/) and [supertest](https://github.com/visionmedia/supertest)
- **Error handling:** centralized to a final middleware 
- **Cross-Origin Resource-Sharing:** enabled by [cors](https://github.com/expressjs/cors)
- **Code style:** [ESLint](https://eslint.org/) and [Prettier](https://prettier.io/), lint rules borrowed from [wesbos](https://github.com/wesbos/eslint-config-wesbos)

## Auth
Authentication and authorization are built on a jwt + refresh tokens and roles such as "user" and "admin". Refresh tokens expire in a week and their purpose is to periodically get jwt tokens which expire in 15 min. The refresh token is sent in a http only cookie while the jwt token inside the "Authorization" header.

The bulk of authorization is done by the `/middleware/authorize.js` middleware, which can be attached on any route.

## API

**Authentication routes:**
`POST /accounts/register`
`POST /accounts/verify-email`
`POST /accounts/authenticate`
`POST /accounts/refresh-token` - refresh the jwt token
`POST /accounts/revoke-token` - revoke the refresh token
`POST /accounts/forgot-password`
`POST /accounts/validate-reset-token`
`POST /accounts/reset-password`
`POST /accounts` - create an account

`GET /accounts` - get all accounts
`GET /accounts/:id`

`PUT /accounts/:id`

`DELETE /accounts/:id`



## Tests

Currently there are integration tests for authentication and authorization. Run the tests with:

    npm run test
    // or
    npm test -- tests/integration/accounts.test.js

## Folder structure

```
src\
 |--build\                         # The app to serve on the frontend
 |--config\                        # Env variables and configuration 
 |--features\                      # Feature based modules
    |-- name                       # A certain feature
        |-- name.controller.js     # A feature's controller
        |-- name.model.js          # A feature's model (may be more)
        |-- name.service.js        # A feature's business logic
 |--middleware\                    # Custom express middlewares
 |--utils\                         # Utility classes and functions
 |--app.js                         # Express app
 |--index.js                       # App entry point
```

## Inspirations

 1. Great auth node + mongo boilerplate
	 - https://jasonwatmore.com/post/2020/05/13/node-mongo-api-with-email-sign-up-verification-authentication-forgot-password
2. Great overall node + mongo boilerplate which also has TESTS!!!
	- https://github.com/hagopj13/node-express-boilerplate

## Final words
Why use it? 
Right. 
Don't use it. 

The resources provided above are way, way better. This is a custom boilerplate made to my needs.
