const bodyParser = require('body-parser')

const bodyParserMiddleware = (app) => {
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: true}));
}

module.exports = bodyParserMiddleware;