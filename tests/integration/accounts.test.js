// https://github.com/hagopj13/node-express-boilerplate/tree/master/tests/integration

const supertest = require('supertest');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('../../utils/db');
const app = require('../../app');
const { SECRET } = require('../../utils/config');
const {
  accountOne,
  accountTwo,
  accountAdmin,
  insertAccounts,
  accountRegistration,
} = require('../fixtures/account.fixture');
const {
  tokenRefreshAccountOne,
  tokenRefreshAccountTwo,
  tokenRefreshAccountTwoExpired,
  tokenRefreshAccountAdmin,
  tokenJwtAccountOne,
  tokenJwtAccountTwo,
  tokenJwtAccountTwoExpired,
  tokenJwtAccountAdmin,
  insertTokensRefresh,
} = require('../fixtures/token.fixture');
const { copyObj } = require('../helpers');

const api = supertest(app);

beforeEach(async () => {
  await db.Account.deleteMany({});
  await db.TokenRefresh.deleteMany({});
});

afterAll(() => {
  mongoose.connection.close();
});

describe('Registration', () => {
  describe('POST /accounts/register', () => {
    test('should return 201 and successfully register account if data ok', async () => {
      await api
        .post('/accounts/register')
        .send(accountRegistration)
        .expect(201);

      const accountFromDb = await db.Account.findOne({
        email: accountRegistration.email,
      });

      expect(accountFromDb).toBeTruthy();
      expect(accountFromDb.password).toBeUndefined();
      expect(accountFromDb.verificationToken).toBeDefined();
      expect(accountFromDb.verfied).toBeUndefined();
      expect(accountFromDb.created).toBeDefined();

      const isHashCorrect = await bcrypt.compare(
        accountRegistration.password,
        accountFromDb.passwordHash
      );

      expect(isHashCorrect).toBe(true);
      expect(accountFromDb).toMatchObject({
        userName: accountRegistration.userName,
        firstName: accountRegistration.firstName,
        lastName: accountRegistration.lastName,
        email: accountRegistration.email,
        role: 'admin',
      });
    });

    test('should return 400 if any essential data missing', async () => {
      const missingUserName = copyObj(accountRegistration);
      delete missingUserName.userName;
      await api.post('/accounts/register').send(missingUserName).expect(400);

      const missingFirstName = copyObj(accountRegistration);
      delete missingFirstName.firstName;
      await api.post('/accounts/register').send(missingFirstName).expect(400);

      const missingLastName = copyObj(accountRegistration);
      delete missingLastName.lastName;
      await api.post('/accounts/register').send(missingLastName).expect(400);

      const missingEmail = copyObj(accountRegistration);
      delete missingEmail.email;
      await api.post('/accounts/register').send(missingEmail).expect(400);

      const missingPassword = copyObj(accountRegistration);
      delete missingPassword.password;
      await api.post('/accounts/register').send(missingPassword).expect(400);

      const missingPasswordConfirm = JSON.parse(
        JSON.stringify(accountRegistration)
      );
      delete missingPasswordConfirm.passwordConfirm;
      await api
        .post('/accounts/register')
        .send(missingPasswordConfirm)
        .expect(400);
    });

    test('should return 400 if any essential data invalid', async () => {
      const passwordTooShort = copyObj(accountRegistration);
      passwordTooShort.password = '1234567';
      await api.post('/accounts/register').send(passwordTooShort).expect(400);

      const userNameTooShort = copyObj(accountRegistration);
      userNameTooShort.userName = '12';
      await api.post('/accounts/register').send(userNameTooShort).expect(400);

      const emailWithoutAt = copyObj(accountRegistration);
      emailWithoutAt.email = 'email.com';
      await api.post('/accounts/register').send(emailWithoutAt).expect(400);
    });

    test('should return 400 if email or userName already in db', async () => {
      await api
        .post('/accounts/register')
        .send(accountRegistration)
        .expect(201);

      const sameUserName = copyObj(accountRegistration);
      sameUserName.email = 'differentTest@mail.com';
      await api.post('/accounts/register').send(sameUserName).expect(400);

      const sameEmail = copyObj(accountRegistration);
      sameEmail.userName = 'differentUserName';
      await api.post('/accounts/register').send(sameEmail).expect(400);
    });
  });

  describe('GET /accounts/verify-email', () => {
    beforeEach(async () => {
      const accountUnverified = copyObj(accountOne);
      delete accountUnverified.verified;
      accountUnverified.verificationToken = '1234567890';
      await insertAccounts([accountUnverified]);
    });

    test('should activate account if token url param is correct', async () => {
      const accountFromDbAtStart = await db.Account.findOne({
        email: accountOne.email,
      });
      expect(accountFromDbAtStart.verified).toBeUndefined();
      expect(accountFromDbAtStart.verificationToken).toBeDefined();

      const response = await api
        .get(
          `/accounts/verify-email?token=${accountFromDbAtStart.verificationToken}`
        )
        .expect(200);
      expect(response.body.message).toBe(
        'Verification successful, you can now login'
      );

      const accountFromDbAtEnd = await db.Account.findOne({
        email: accountOne.email,
      });
      expect(accountFromDbAtEnd.verified).toBeDefined();
      expect(accountFromDbAtEnd.verificationToken).toBeUndefined();
    });

    test('should return 400 if token url param is wrong or missing', async () => {
      await api.get('/accounts/verify-email?token=wrongToken').expect(400);
      await api.get('/accounts/verify-email').expect(400);

      const accountFromDbAtEnd = await db.Account.findOne({
        email: accountOne.email,
      });
      expect(accountFromDbAtEnd.verified).toBeUndefined();
      expect(accountFromDbAtEnd.verificationToken).toBe('1234567890');
    });
  });

  describe('POST /accounts/verify-email', () => {
    beforeEach(async () => {
      const accountUnverified = copyObj(accountOne);
      delete accountUnverified.verified;
      accountUnverified.verificationToken = '1234567890';
      await insertAccounts([accountUnverified]);
    });

    test('should activate account if token correct', async () => {
      const accountFromDbAtStart = await db.Account.findOne({
        email: accountOne.email,
      });
      expect(accountFromDbAtStart.verified).toBeUndefined();
      expect(accountFromDbAtStart.verificationToken).toBeDefined();

      const response = await api
        .post('/accounts/verify-email')
        .send({ token: accountFromDbAtStart.verificationToken })
        .expect(200);
      expect(response.body.message).toBe(
        'Verification successful, you can now login'
      );

      const accountFromDbAtEnd = await db.Account.findOne({
        email: accountOne.email,
      });
      expect(accountFromDbAtEnd.verified).toBeDefined();
      expect(accountFromDbAtEnd.verificationToken).toBeUndefined();
    });

    test('should return 400 if token is wrong or missing', async () => {
      await api
        .post('/accounts/verify-email')
        .send({ token: 'wrongToken' })
        .expect(400);

      await api.post('/accounts/verify-email').expect(400);

      const accountFromDbAtEnd = await db.Account.findOne({
        email: accountOne.email,
      });
      expect(accountFromDbAtEnd.verified).toBeUndefined();
      expect(accountFromDbAtEnd.verificationToken).toBe('1234567890');
    });
  });
});

describe('Authenticate', () => {
  describe('POST /accounts/authenticate', () => {
    beforeEach(async () => {
      await insertAccounts([accountOne, accountTwo, accountAdmin]);
    });

    test('should return 200 and a valid jwt if email & passsword are correct', async () => {
      const credentialsLogin = {
        email: accountTwo.email,
        password: '12345678',
      };

      const response = await api
        .post('/accounts/authenticate')
        .send(credentialsLogin)
        .expect(200)
        .expect('Content-Type', /application\/json/);

      expect(response.body).toMatchObject({
        userName: accountTwo.userName,
        firstName: accountTwo.firstName,
        lastName: accountTwo.lastName,
        email: accountTwo.email,
        role: accountTwo.role,
      });

      expect(response.body.tokenJwt).toBeDefined();
      const jwtDecoded = jwt.verify(response.body.tokenJwt, SECRET);
      expect(jwtDecoded.id).toBe(response.body.id);

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(jwtDecoded.id).toBe(accountFromDb.id);
    });

    test('should return 401 if email not found', async () => {
      const credentialsLogin = {
        email: `${accountTwo.email}wrong`,
        password: '12345678',
      };

      const response = await api
        .post('/accounts/authenticate')
        .send(credentialsLogin)
        .expect(401)
        .expect('Content-Type', /application\/json/);

      expect(response.body.message).toBe('incorrect email or password');
    });

    test('should return 401 if password is worng', async () => {
      const credentialsLogin = {
        email: accountTwo.email,
        password: 'wrongPassword',
      };

      const response = await api
        .post('/accounts/authenticate')
        .send(credentialsLogin)
        .expect(401)
        .expect('Content-Type', /application\/json/);

      expect(response.body.message).toBe('incorrect email or password');
    });
  });
});

describe('Token manipulations', () => {
  describe('POST /accounts/refresh-token', () => {
    beforeEach(async () => {
      await insertAccounts([accountOne, accountTwo, accountAdmin]);
      await insertTokensRefresh([
        tokenRefreshAccountOne,
        tokenRefreshAccountTwo,
        tokenRefreshAccountAdmin,
        tokenRefreshAccountTwoExpired,
      ]);
    });

    test('should return a new jwt token if refresh-token is valid', async () => {
      const response = await api
        .post('/accounts/refresh-token')
        .set('Cookie', [`tokenRefresh=${tokenRefreshAccountTwo.token}`])
        .expect(200);

      expect(response.body.tokenJwt).toBeDefined();
      const jwtDecoded = jwt.verify(response.body.tokenJwt, SECRET);
      expect(jwtDecoded.id).toBe(response.body.id);

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(jwtDecoded.id).toBe(accountFromDb.id);
    });

    test('should refresh the refresh token', async () => {
      const response = await api
        .post('/accounts/refresh-token')
        .set('Cookie', [`tokenRefresh=${tokenRefreshAccountTwo.token}`])
        .expect(200);

      const tokenRefreshReceived = response.headers['set-cookie'][0]
        .split(',')
        .map((item) => item.split(';')[0])[0];

      const isCookieTokenRefresh =
        tokenRefreshReceived.startsWith('tokenRefresh=');
      expect(isCookieTokenRefresh).toBeTruthy();
      expect(tokenRefreshReceived).not.toBe(
        `tokenRefresh=${tokenRefreshAccountTwo.token}`
      );
    });

    test('should return 400 if refresh-token is invalid or missing', async () => {
      const responseWrongToken = await api
        .post('/accounts/refresh-token')
        .set('Cookie', [`tokenRefresh=wrongToken`])
        .expect(400);
      const responseMissingToken = await api
        .post('/accounts/refresh-token')
        .expect(400);

      expect(responseWrongToken.body.tokenJwt).toBeUndefined();
      expect(responseMissingToken.body.tokenJwt).toBeUndefined();
      expect(responseWrongToken.body.message).toBe('invalid token');
      expect(responseMissingToken.body.message).toBe('invalid token');
    });

    test('should return 401 if refresh token is expired', async () => {
      const response = await api
        .post('/accounts/refresh-token')
        .set('Cookie', [`tokenRefresh=${tokenRefreshAccountTwoExpired.token}`])
        .expect(401);

      expect(response.body.tokenJwt).toBeUndefined();
      expect(response.body.message).toBe('expired token');
    });
  });

  describe('POST /accounts/revoke-token', () => {
    beforeEach(async () => {
      await insertAccounts([accountOne, accountTwo, accountAdmin]);
      await insertTokensRefresh([
        tokenRefreshAccountOne,
        tokenRefreshAccountTwo,
        tokenRefreshAccountAdmin,
        tokenRefreshAccountTwoExpired,
      ]);
    });

    test('should return 400 if invalid or missing jwt is sent in Auth header', async () => {
      const response = await api
        .post('/accounts/revoke-token')
        .set('Authorization', `bearer invalid_jwt_token`)
        .set('Cookie', [`tokenRefresh=${tokenRefreshAccountTwo.token}`])
        .send({ tokenRefresh: tokenRefreshAccountTwo.token })
        .expect(400);

      const response2 = await api
        .post('/accounts/revoke-token')
        .set('Cookie', [`tokenRefresh=${tokenRefreshAccountTwo.token}`])
        .send({ tokenRefresh: tokenRefreshAccountTwo.token })
        .expect(400);

      expect(response.body.message).toBe('invalid token');
      expect(response2.body.message).toBe('invalid token');

      const tokenRefreshFromDb = await db.TokenRefresh.findOne({
        token: tokenRefreshAccountTwo.token,
      });
      expect(tokenRefreshFromDb.revokedByIp).toBeUndefined();
      expect(tokenRefreshFromDb.revoked).toBeUndefined();
    });

    test('should return 401 if jwt token is expired', async () => {
      const response = await api
        .post('/accounts/revoke-token')
        .set('Authorization', `bearer ${tokenJwtAccountTwoExpired}`)
        .set('Cookie', [`tokenRefresh=${tokenRefreshAccountTwo.token}`])
        .send({ tokenRefresh: tokenRefreshAccountTwo.token })
        .expect(401);

      expect(response.body.message).toBe('expired token');

      const tokenRefreshFromDb = await db.TokenRefresh.findOne({
        token: tokenRefreshAccountTwo.token,
      });
      expect(tokenRefreshFromDb.revokedByIp).toBeUndefined();
      expect(tokenRefreshFromDb.revoked).toBeUndefined();
    });

    test('should return 400 if missing refresh token', async () => {
      await api
        .post('/accounts/revoke-token')
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .expect(400);

      const tokenRefreshFromDb = await db.TokenRefresh.findOne({
        token: tokenRefreshAccountTwo.token,
      });
      expect(tokenRefreshFromDb.revokedByIp).toBeUndefined();
      expect(tokenRefreshFromDb.revoked).toBeUndefined();
    });

    test('should return 401 if refresh token is expired', async () => {
      const response = await api
        .post('/accounts/revoke-token')
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .set('Cookie', [`tokenRefresh=${tokenRefreshAccountTwoExpired.token}`])
        .expect(401);

      expect(response.body.message).toBe('expired token');

      const tokenRefreshFromDb = await db.TokenRefresh.findOne({
        token: tokenRefreshAccountTwo.token,
      });
      expect(tokenRefreshFromDb.revokedByIp).toBeUndefined();
      expect(tokenRefreshFromDb.revoked).toBeUndefined();
    });

    test("should successfully revoke a user's refresh token if refresh token sent", async () => {
      await api
        .post('/accounts/revoke-token')
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .set('Cookie', [`tokenRefresh=${tokenRefreshAccountTwo.token}`])
        .send({ tokenRefresh: tokenRefreshAccountTwo.token })
        .expect(200);

      const tokenRefreshFromDb = await db.TokenRefresh.findOne({
        token: tokenRefreshAccountTwo.token,
      });
      expect(tokenRefreshFromDb.revokedByIp).toBeDefined();
      expect(tokenRefreshFromDb.revoked).toBeDefined();
    });

    test("should successfully revoke a user's refresh token if refresh token is not sent", async () => {
      await api
        .post('/accounts/revoke-token')
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .set('Cookie', [`tokenRefresh=${tokenRefreshAccountTwo.token}`])
        .expect(200);

      const tokenRefreshFromDb = await db.TokenRefresh.findOne({
        token: tokenRefreshAccountTwo.token,
      });
      expect(tokenRefreshFromDb.revokedByIp).toBeDefined();
      expect(tokenRefreshFromDb.revoked).toBeDefined();
    });

    test('should return 401 if user revokes not his refresh token', async () => {
      await api
        .post('/accounts/revoke-token')
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .set('Cookie', [`tokenRefresh=${tokenRefreshAccountTwo.token}`])
        .send({ tokenRefresh: tokenRefreshAccountOne.token })
        .expect(401);

      const tokenRefreshFromDb = await db.TokenRefresh.findOne({
        token: tokenRefreshAccountOne.token,
      });
      expect(tokenRefreshFromDb.revokedByIp).toBeUndefined();
      expect(tokenRefreshFromDb.revoked).toBeUndefined();
    });

    test('should successfully revoke any refresh token sent by an admin', async () => {
      await api
        .post('/accounts/revoke-token')
        .set('Authorization', `bearer ${tokenJwtAccountAdmin}`)
        .set('Cookie', [`tokenRefresh=${tokenRefreshAccountAdmin}`])
        .send({ tokenRefresh: tokenRefreshAccountOne.token })
        .expect(200);

      const tokenRefreshFromDb = await db.TokenRefresh.findOne({
        token: tokenRefreshAccountOne.token,
      });
      expect(tokenRefreshFromDb.revokedByIp).toBeDefined();
      expect(tokenRefreshFromDb.revoked).toBeDefined();
    });
  });
});

// test('fails with 401 and error message if username not found', async () => {
//   const userToLogin = {
//     username: 'wrongLogin',
//     password: 'admin',
//   };

//   const response = await api
//     .post('/api/login')
//     .send(userToLogin)
//     .expect(401)
//     .expect('Content-Type', /application\/json/);

//   expect(response.body.error).toBe('invalid username or password');
//   expect(response.body.token).toBeUndefined();
// });

// test('fails with 401 and error message if password is wrong', async () => {
//   const userToLogin = {
//     username: 'admin',
//     password: 'wrongPassword',
//   };

//   const response = await api
//     .post('/api/login')
//     .send(userToLogin)
//     .expect(401)
//     .expect('Content-Type', /application\/json/);

//   expect(response.body.error).toBe('invalid username or password');
//   expect(response.body.token).toBeUndefined();
// });
