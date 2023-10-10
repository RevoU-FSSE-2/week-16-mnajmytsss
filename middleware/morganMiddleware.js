const morgan = require('morgan')

const morganMiddleware = (app) => {
    app.use(morgan('dev'));
}

module.exports = morganMiddleware;