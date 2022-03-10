// https://github.com/hagopj13/node-express-boilerplate/tree/master/tests/integration

const supertest = require('supertest');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('../../utils/db');
const app = require('../../app');
const { SECRET } = require('../../utils/config');
const role = require('../../utils/role');
const {
  accountOne,
  accountTwo,
  accountTokenResetExpired,
  accountAdmin,
  insertAccounts,
  accountRegistration,
} = require('../fixtures/account.fixture');
const {
  tokenRefreshAccountOne,
  tokenRefreshAccountTwo,
  tokenRefreshAccountAdmin,
  tokenRefreshAccountTwoExpired,
  tokenJwtAccountAdminExpired,
  tokenJwtAccountOne,
  tokenJwtAccountTwo,
  tokenJwtAccountTwoExpired,
  tokenJwtAccountAdmin,
  insertTokensRefresh,
} = require('../fixtures/token.fixture');
const { copyObj, getANonExistingId } = require('../helpers');

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
        role: role.Admin,
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

      const passwordsMismatch = copyObj(accountRegistration);
      passwordsMismatch.password = '12345678';
      passwordsMismatch.passwordConfirm = '12345679';
      await api.post('/accounts/register').send(passwordsMismatch).expect(400);

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

describe('Authentication', () => {
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

      expect(response.body).toEqual({ message: 'invalid token' });
      expect(response2.body).toEqual({ message: 'invalid token' });

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

describe('Reseting the password', () => {
  beforeEach(async () => {
    await insertAccounts([
      accountOne,
      accountTwo,
      accountAdmin,
      accountTokenResetExpired,
    ]);
  });

  describe('POST /accounts/forgot-password', () => {
    test('should return 400 if no email sent', async () => {
      await api.post('/accounts/forgot-password').expect(400);
    });

    test('should return 400 if invalid email sent', async () => {
      await api
        .post('/accounts/forgot-password')
        .send({ email: 'invalid_email' })
        .expect(400);
    });

    test('should return 200 if email not found in db', async () => {
      await api
        .post('/accounts/forgot-password')
        .send({ email: 'email_that_is_not_in_db@mail.com' })
        .expect(200);
    });

    test('should create a reset token on the account in db if email found', async () => {
      await api
        .post('/accounts/forgot-password')
        .send({ email: accountTwo.email })
        .expect(200);

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb.resetToken.token).toBeDefined();
      expect(accountFromDb.resetToken.token).not.toBe(
        accountTwo.resetToken.token
      );
    });
  });

  describe('POST /accounts/reset-password', () => {
    test('should return 400 if any of essential data is missing', async () => {
      await api
        .post('/accounts/reset-password')
        .send({ token: accountTwo.resetToken.token, password: '87654321' })
        .expect(400);

      await api
        .post('/accounts/reset-password')
        .send({
          token: accountTwo.resetToken.token,
          passwordConfirm: '87654321',
        })
        .expect(400);

      await api
        .post('/accounts/reset-password')
        .send({ password: '87654321', passwordConfirm: '87654321' })
        .expect(400);

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb.passwordHash).toBe(accountTwo.passwordHash);
    });

    test('should return 400 if password too short', async () => {
      await api
        .post('/accounts/reset-password')
        .send({
          token: accountTwo.resetToken.token,
          password: '7654321',
          passwordConfirm: '7654321',
        })
        .expect(400);

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb.passwordHash).toBe(accountTwo.passwordHash);
    });

    test('should return 400 if passwords mismatch', async () => {
      await api
        .post('/accounts/reset-password')
        .send({
          token: accountTwo.resetToken.token,
          password: '97654321',
          passwordConfirm: '87654321',
        })
        .expect(400);

      await api
        .post('/accounts/reset-password')
        .send({
          token: accountTwo.resetToken.token,
          password: '87654321',
          passwordConfirm: '97654321',
        })
        .expect(400);

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb.passwordHash).toBe(accountTwo.passwordHash);
    });

    test('should return 400 if reset token expired', async () => {
      await api
        .post('/accounts/reset-password')
        .send({
          token: accountTokenResetExpired.resetToken.token,
          password: '87654321',
          passwordConfirm: '87654321',
        })
        .expect(400);

      const accountFromDb = await db.Account.findOne({
        email: accountTokenResetExpired.email,
      });
      expect(accountFromDb.passwordHash).toBe(
        accountTokenResetExpired.passwordHash
      );
    });

    test('should change password if data valid', async () => {
      await api
        .post('/accounts/reset-password')
        .send({
          token: accountTwo.resetToken.token,
          password: '87654321',
          passwordConfirm: '87654321',
        })
        .expect(200);

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb.passwordHash).toBeDefined();
      expect(accountFromDb.resetToken.token).toBeUndefined();

      const isNewPasswordCorrect = await bcrypt.compare(
        '87654321',
        accountFromDb.passwordHash
      );
      const isOldPasswordCorrect = await bcrypt.compare(
        '12345678',
        accountFromDb.passwordHash
      );

      expect(isNewPasswordCorrect).toBe(true);
      expect(isOldPasswordCorrect).toBe(false);
    });
  });
});

describe('Viewing the accounts', () => {
  beforeEach(async () => {
    await insertAccounts([
      accountOne,
      accountTwo,
      accountAdmin,
      accountTokenResetExpired,
    ]);
  });

  describe('GET /accounts', () => {
    test('should return 400 if invalid or missing jwt is sent in Auth header', async () => {
      const response = await api
        .get('/accounts')
        .set('Authorization', `bearer invalid_jwt_token`)
        .expect(400);

      const response2 = await api.get('/accounts').expect(400);

      expect(response.body).toEqual({ message: 'invalid token' });
      expect(response2.body).toEqual({ message: 'invalid token' });
    });

    test('should return 401 if jwt token is expired', async () => {
      const response = await api
        .get('/accounts')
        .set('Authorization', `bearer ${tokenJwtAccountAdminExpired}`)
        .expect(401);

      expect(response.body).toEqual({ message: 'expired token' });
    });

    test('should return 401 if user', async () => {
      const response = await api
        .get('/accounts')
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .expect(401);

      expect(response.body).toEqual({ message: 'unauthorized' });
    });

    test('should return accounts if admin and token valid', async () => {
      const response = await api
        .get('/accounts')
        .set('Authorization', `bearer ${tokenJwtAccountAdmin}`)
        .expect(200);

      expect(response.body).toHaveLength(4);
    });
  });

  describe('GET /accounts/:id', () => {
    test('should return 400 if invalid or missing jwt is sent in Auth header', async () => {
      const response = await api
        .get(`/accounts/${accountOne._id}`)
        .set('Authorization', `bearer invalid_jwt_token`)
        .expect(400);

      const response2 = await api
        .get(`/accounts/${accountOne._id}`)
        .expect(400);

      expect(response.body).toEqual({ message: 'invalid token' });
      expect(response2.body).toEqual({ message: 'invalid token' });
    });

    test('should return 401 if jwt token is expired', async () => {
      const response = await api
        .get(`/accounts/${accountOne._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdminExpired}`)
        .expect(401);

      expect(response.body).toEqual({ message: 'expired token' });
    });

    test('should return 401 if user requests not his account', async () => {
      const response = await api
        .get(`/accounts/${accountOne._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .expect(401);

      expect(response.body).toEqual({ message: 'unauthorized' });
    });

    test('should return account if user requests his own account', async () => {
      const response = await api
        .get(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .expect(200);

      expect(response.body).toMatchObject({
        id: accountTwo._id.toString(),
        userName: accountTwo.userName,
        firstName: accountTwo.firstName,
        lastName: accountTwo.lastName,
        email: accountTwo.email,
      });
    });

    test('should return account if admin requests any account', async () => {
      const response = await api
        .get(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdmin}`)
        .expect(200);

      expect(response.body).toMatchObject({
        id: accountTwo._id.toString(),
        userName: accountTwo.userName,
        firstName: accountTwo.firstName,
        lastName: accountTwo.lastName,
        email: accountTwo.email,
      });
    });

    test('should return 404 if no account in db', async () => {
      const response = await api
        .get(`/accounts/${await getANonExistingId()}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdmin}`)
        .expect(404);

      expect(response.body).toMatchObject({ message: 'account not found' });
    });
  });
});

describe('Modifying the accounts', () => {
  beforeEach(async () => {
    await insertAccounts([
      accountOne,
      accountTwo,
      accountAdmin,
      accountTokenResetExpired,
    ]);
  });

  describe('PUT /accounts/:id', () => {
    test('should return 400 if invalid or missing jwt is sent in Auth header', async () => {
      const response = await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer invalid_jwt_token`)
        .send({ firstName: 'new_firstName' })
        .expect(400);

      const response2 = await api
        .put(`/accounts/${accountTwo._id}`)
        .send({ firstName: 'new_firstName' })
        .expect(400);

      expect(response.body).toEqual({ message: 'invalid token' });
      expect(response2.body).toEqual({ message: 'invalid token' });
    });

    test('should return 401 if jwt token is expired', async () => {
      const response = await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdminExpired}`)
        .send({ firstName: 'new_firstName' })
        .expect(401);

      expect(response.body).toEqual({ message: 'expired token' });
    });

    test('should return 401 if user changes not his own account', async () => {
      const response = await api
        .put(`/accounts/${accountOne._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .send({ firstName: 'new_firstName' });

      expect(response.body).toEqual({ message: 'unauthorized' });
    });

    test('should return 404 if no account in db', async () => {
      const response = await api
        .put(`/accounts/${await getANonExistingId()}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdmin}`)
        .send({ firstName: 'new_firstName_changed_by_admin' })
        .expect(404);

      expect(response.body).toMatchObject({ message: 'account not found' });
    });

    test('should return 400 if userName already taken', async () => {
      const response = await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdmin}`)
        .send({ userName: accountOne.userName })
        .expect(400);

      expect(response.body).toEqual({
        message: `username "${accountOne.userName}" is already taken`,
      });
    });

    test('should return 400 if email already taken', async () => {
      const response = await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdmin}`)
        .send({ email: accountOne.email })
        .expect(400);

      expect(response.body).toEqual({
        message: `email "${accountOne.email}" is already taken`,
      });
    });

    test('should update account if user requests his own account', async () => {
      const response = await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .send({ firstName: 'new_firstName' })
        .expect(200);

      expect(response.body).toMatchObject({
        id: accountTwo._id.toString(),
        userName: accountTwo.userName,
        firstName: 'new_firstName',
        lastName: accountTwo.lastName,
        email: accountTwo.email,
      });

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb).toMatchObject({
        userName: accountTwo.userName,
        firstName: 'new_firstName',
        lastName: accountTwo.lastName,
        email: accountTwo.email,
      });
    });

    test('should update account if admin requests any account', async () => {
      const response = await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdmin}`)
        .send({ firstName: 'new_firstName_changed_by_admin' })
        .expect(200);

      expect(response.body).toMatchObject({
        id: accountTwo._id.toString(),
        userName: accountTwo.userName,
        firstName: 'new_firstName_changed_by_admin',
        lastName: accountTwo.lastName,
        email: accountTwo.email,
      });

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb).toMatchObject({
        userName: accountTwo.userName,
        firstName: 'new_firstName_changed_by_admin',
        lastName: accountTwo.lastName,
        email: accountTwo.email,
      });
    });

    test('should return 400 if password too short', async () => {
      await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .send({ password: '7654321', passwordConfirm: '7654321' })
        .expect(400);

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb.passwordHash).toBe(accountTwo.passwordHash);
    });

    test('should return 400 if passwords mismatch', async () => {
      await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .send({
          password: '97654321',
          passwordConfirm: '87654321',
        })
        .expect(400);

      await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .send({
          password: '87654321',
          passwordConfirm: '97654321',
        })
        .expect(400);

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb.passwordHash).toBe(accountTwo.passwordHash);
    });

    test('should hash the password if password changed', async () => {
      const response = await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .send({ password: '87654321', passwordConfirm: '87654321' })
        .expect(200);

      expect(response.body).toMatchObject({
        id: accountTwo._id.toString(),
        userName: accountTwo.userName,
        firstName: accountTwo.firstName,
        lastName: accountTwo.lastName,
        email: accountTwo.email,
      });

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      const isNewPasswordCorrect = await bcrypt.compare(
        '87654321',
        accountFromDb.passwordHash
      );
      const isOldPasswordCorrect = await bcrypt.compare(
        '12345678',
        accountFromDb.passwordHash
      );

      expect(isNewPasswordCorrect).toBe(true);
      expect(isOldPasswordCorrect).toBe(false);
    });

    test('should ignore if user attempts to change role', async () => {
      const response = await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .send({ role: role.Admin })
        .expect(200);

      expect(response.body).toMatchObject({
        id: accountTwo._id.toString(),
        userName: accountTwo.userName,
        firstName: accountTwo.firstName,
        lastName: accountTwo.lastName,
        email: accountTwo.email,
        role: role.User,
      });

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb).toMatchObject({
        userName: accountTwo.userName,
        firstName: accountTwo.firstName,
        lastName: accountTwo.lastName,
        email: accountTwo.email,
        role: role.User,
      });
    });

    test('should apply role change if admin', async () => {
      const response = await api
        .put(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdmin}`)
        .send({ role: role.Admin })
        .expect(200);

      expect(response.body).toMatchObject({
        id: accountTwo._id.toString(),
        userName: accountTwo.userName,
        firstName: accountTwo.firstName,
        lastName: accountTwo.lastName,
        email: accountTwo.email,
        role: role.Admin,
      });

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb).toMatchObject({
        userName: accountTwo.userName,
        firstName: accountTwo.firstName,
        lastName: accountTwo.lastName,
        email: accountTwo.email,
        role: role.Admin,
      });
    });
  });

  describe('DELETE /accounts/:id', () => {
    test('should return 400 if invalid or missing jwt is sent in Auth header', async () => {
      const response = await api
        .delete(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer invalid_jwt_token`)
        .expect(400);

      const response2 = await api
        .delete(`/accounts/${accountTwo._id}`)
        .expect(400);

      expect(response.body).toEqual({ message: 'invalid token' });
      expect(response2.body).toEqual({ message: 'invalid token' });
    });

    test('should return 401 if jwt token is expired', async () => {
      const response = await api
        .delete(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdminExpired}`)
        .expect(401);

      expect(response.body).toEqual({ message: 'expired token' });
    });

    test('should return 401 if user deletes not his own account', async () => {
      const response = await api
        .delete(`/accounts/${accountOne._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`);

      expect(response.body).toEqual({ message: 'unauthorized' });
    });

    test('should return 404 if no account in db', async () => {
      const response = await api
        .delete(`/accounts/${await getANonExistingId()}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdmin}`)
        .expect(404);

      expect(response.body).toMatchObject({ message: 'account not found' });
    });

    test('should delete account if user deletes his own account', async () => {
      const response = await api
        .delete(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountTwo}`)
        .expect(200);

      expect(response.body).toMatchObject({
        message: 'account deleted successfully',
      });

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb).toBeNull();
    });

    test('should update account if admin requests any account', async () => {
      const response = await api
        .delete(`/accounts/${accountTwo._id}`)
        .set('Authorization', `bearer ${tokenJwtAccountAdmin}`)
        .expect(200);

      expect(response.body).toMatchObject({
        message: 'account deleted successfully',
      });

      const accountFromDb = await db.Account.findOne({
        email: accountTwo.email,
      });
      expect(accountFromDb).toBeNull();
    });
  });
});
