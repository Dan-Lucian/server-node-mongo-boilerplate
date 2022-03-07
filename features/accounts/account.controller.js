/* eslint-disable no-shadow */
const express = require('express');

const router = express.Router();
const Joi = require('joi');
const Role = require('../../utils/role');
const authorize = require('../../middleware/authorize');
const validateRequest = require('../../middleware/validate-request');
const accountService = require('./account.service');

// routes
router.post('/register', registerSchema, register);
router.post('/verify-email', verifyEmailSchema, verifyEmail);
router.post('/authenticate', authenticateSchema, authenticate);
router.post('/refresh-token', refreshToken);
router.post('/revoke-token', authorize(), revokeTokenSchema, revokeToken);
router.post('/forgot-password', forgotPasswordSchema, forgotPassword);
router.post(
  '/validate-reset-token',
  validateResetTokenSchema,
  validateResetToken
);
router.post('/reset-password', resetPasswordSchema, resetPassword);
router.get('/', authorize(Role.Admin), getAll);
router.get('/:id', authorize(), getById);
router.post('/', authorize(Role.Admin), createSchema, create);
router.put('/:id', authorize(), updateSchema, update);
router.delete('/:id', authorize(), _delete);

module.exports = router;

function registerSchema(request, response, next) {
  const schema = Joi.object({
    firstname: Joi.string().required(),
    lastname: Joi.string().required(),
    username: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(5).required(),
    passwordConfirmed: Joi.string().valid(Joi.ref('password')).required(),
  });
  validateRequest(request, next, schema);
}

async function register(request, response, next) {
  await accountService.register(request.body, request.get('origin'));

  response.json({
    message:
      'Registration successful, please check your email for verification instructions',
  });
}

function verifyEmailSchema(request, response, next) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  validateRequest(request, next, schema);
}

async function verifyEmail(request, response, next) {
  await accountService.verifyEmail(request.body);

  response.json({ message: 'Verification successful, you can now login' });
}

function authenticateSchema(request, response, next) {
  const schema = Joi.object({
    email: Joi.string().required(),
    password: Joi.string().required(),
  });
  validateRequest(request, next, schema);
}

async function authenticate(request, response, next) {
  const { email, password } = request.body;
  const ipAddress = request.ip;

  const { tokenRefresh, ...account } = await accountService.authenticate({
    email,
    password,
    ipAddress,
  });

  putTokenInCookie(response, tokenRefresh);
  response.json(account);
}

async function refreshToken(request, response, next) {
  const tokenRefreshReceived = request.cookies.tokenRefresh;
  const ipAddress = request.ip;

  const { tokenRefresh, ...account } = await accountService.refreshToken({
    tokenRefreshReceived,
    ipAddress,
  });

  putTokenInCookie(response, tokenRefresh);
  response.json(account);
}

function revokeTokenSchema(request, response, next) {
  const schema = Joi.object({
    token: Joi.string().empty(''),
  });
  validateRequest(request, next, schema);
}

function revokeToken(request, response, next) {
  // accept token from request body or cookie
  const token = request.body.token || request.cookies.tokenRefresh;
  const ipAddress = request.ip;

  if (!token)
    return response.status(400).json({ message: 'Token is required' });

  // users can revoke their own tokens and admins can revoke any tokens
  if (!request.user.ownsToken(token) && request.user.role !== Role.Admin) {
    return response.status(401).json({ message: 'Unauthorized' });
  }

  accountService
    .revokeToken({ token, ipAddress })
    .then(() => response.json({ message: 'Token revoked' }))
    .catch(next);
}

function forgotPasswordSchema(request, response, next) {
  const schema = Joi.object({
    email: Joi.string().email().required(),
  });
  validateRequest(request, next, schema);
}

function forgotPassword(request, response, next) {
  accountService
    .forgotPassword(request.body, request.get('origin'))
    .then(() =>
      response.json({
        message: 'Please check your email for password reset instructions',
      })
    )
    .catch(next);
}

function validateResetTokenSchema(request, response, next) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  validateRequest(request, next, schema);
}

function validateResetToken(request, response, next) {
  accountService
    .validateResetToken(request.body)
    .then(() => response.json({ message: 'Token is valid' }))
    .catch(next);
}

function resetPasswordSchema(request, response, next) {
  const schema = Joi.object({
    token: Joi.string().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
  });
  validateRequest(request, next, schema);
}

function resetPassword(request, response, next) {
  accountService
    .resetPassword(request.body)
    .then(() =>
      response.json({ message: 'Password reset successful, you can now login' })
    )
    .catch(next);
}

function getAll(request, response, next) {
  accountService
    .getAll()
    .then((accounts) => response.json(accounts))
    .catch(next);
}

function getById(request, response, next) {
  // users can get their own account and admins can get any account
  if (
    request.params.id !== request.user.id &&
    request.user.role !== Role.Admin
  ) {
    return response.status(401).json({ message: 'Unauthorized' });
  }

  accountService
    .getById(request.params.id)
    .then((account) =>
      account ? response.json(account) : response.sendStatus(404)
    )
    .catch(next);
}

function createSchema(request, response, next) {
  const schema = Joi.object({
    title: Joi.string().required(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
    role: Joi.string().valid(Role.Admin, Role.User).required(),
  });
  validateRequest(request, next, schema);
}

function create(request, response, next) {
  accountService
    .create(request.body)
    .then((account) => response.json(account))
    .catch(next);
}

function updateSchema(request, response, next) {
  const schemaRules = {
    title: Joi.string().empty(''),
    firstName: Joi.string().empty(''),
    lastName: Joi.string().empty(''),
    email: Joi.string().email().empty(''),
    password: Joi.string().min(6).empty(''),
    confirmPassword: Joi.string().valid(Joi.ref('password')).empty(''),
  };

  // only admins can update role
  if (request.user.role === Role.Admin) {
    schemaRules.role = Joi.string().valid(Role.Admin, Role.User).empty('');
  }

  const schema = Joi.object(schemaRules).with('password', 'confirmPassword');
  validateRequest(request, next, schema);
}

function update(request, response, next) {
  // users can update their own account and admins can update any account
  if (
    request.params.id !== request.user.id &&
    request.user.role !== Role.Admin
  ) {
    return response.status(401).json({ message: 'Unauthorized' });
  }

  accountService
    .update(request.params.id, request.body)
    .then((account) => response.json(account))
    .catch(next);
}

function _delete(request, response, next) {
  // users can delete their own account and admins can delete any account
  if (
    request.params.id !== request.user.id &&
    request.user.role !== Role.Admin
  ) {
    return response.status(401).json({ message: 'Unauthorized' });
  }

  accountService
    .delete(request.params.id)
    .then(() => response.json({ message: 'Account deleted successfully' }))
    .catch(next);
}

// helper functions

function putTokenInCookie(response, token) {
  // create cookie with refresh token that expires in 7 days
  const cookieOptions = {
    httpOnly: true,
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  };
  response.cookie('tokenRefresh', token, cookieOptions);
}
