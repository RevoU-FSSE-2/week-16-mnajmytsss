const bodyParserMiddleware = require("./bodyParserMiddleware");
const corsMiddleware = require("./corsMiddleware");
const databaseMiddleware = require('./databaseMiddleware')
const helmetMiddleware = require("./helmetMiddleware");
const morganMiddleware = require("./morganMiddleware");
const requestMiddleware = require("./requestMiddleware");
const cookieMiddleware = require('./cookieMiddleware')

const useMiddleware = (app) => {
    app.use(requestMiddleware);
    helmetMiddleware(app);
    cookieMiddleware(app);
    bodyParserMiddleware(app);
    corsMiddleware(app);
    morganMiddleware(app);
    app.use(databaseMiddleware);
}

module.exports = useMiddleware;
