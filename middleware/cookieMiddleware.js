const cookieParser = require('cookie-parser')

const cookieMiddleware = (app) => {
  app.use(cookieParser());
};

module.exports = cookieMiddleware;