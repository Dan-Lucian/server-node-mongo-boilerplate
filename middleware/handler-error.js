/* eslint-disable no-case-declarations */
module.exports = errorHandler;

function errorHandler(error, request, response, next) {
  switch (true) {
    case typeof error === 'string':
      // custom application error
      const is404 = error.toLowerCase().endsWith('not found');
      const statusCode = is404 ? 404 : 400;
      return response.status(statusCode).json({ message: error });

    case error.name === 'ValidationError':
      // mongoose validation error
      return response
        .status(400)
        .json({ message: `${error.name}: ${error.message}` });

    case error.name === 'UnauthorizedError':
      // jwt authentication error
      return response.status(401).json({ message: 'Unauthorized' });

    case error.name === 'JsonWebTokenError':
      return response.status(401).json({ error: 'invalid token' });

    default:
      return response
        .status(500)
        .json({ message: `${error.name}: ${error.message}` });
  }
}
