const jwt = require('jsonwebtoken');
const Account = require('../features/accounts/account.model');
const TokenRefresh = require('../features/accounts/token-refresh.model');
const { SECRET } = require('../utils/config');

module.exports = authorize;

function authorize(roles = []) {
  // roles param can be a single role string (e.g. Role.User or 'User')
  // or an array of roles (e.g. [Role.Admin, Role.User] or ['Admin', 'User'])
  let arrayRoles = roles;
  if (typeof roles === 'string') {
    arrayRoles = [roles];
  }

  return [
    // authenticate JWT token and attach user to request object (request.user)
    async (request, response, next) => {
      const authorization = request.get('authorization');
      if (authorization && authorization.toLowerCase().startsWith('bearer ')) {
        const tokenDecoded = jwt.verify(authorization.substring(7), SECRET);
        request.user = tokenDecoded;
        // if (tokenDecoded) {
        //   request.user = await Account.findById(tokenDecoded.id);
        // }
      }

      next();
    },

    // authorize based on user role
    async (request, response, next) => {
      const account = await Account.findById(request.user.id);
      const TokensRefresh = await TokenRefresh.find({ account: account.id });

      if (
        !account ||
        (arrayRoles.length && !arrayRoles.includes(account.role))
      ) {
        // account no longer exists or role not authorized
        return response.status(401).json({ message: 'Unauthorized' });
      }

      // authentication and authorization successful
      request.user.role = account.role;
      request.user.ownsToken = (token) =>
        !!TokensRefresh.find((x) => x.token === token);
      next();
    },
  ];
}
