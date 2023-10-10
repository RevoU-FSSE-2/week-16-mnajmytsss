const helmet = require('helmet')

const helmetMiddleware = (app) => {
    app.use(helmet());
    app.use(
        helmet({
            xFrameOptions: {action: "deny"},
            crossOriginEmbedderPolicy: true,
        })
    );
};

module.exports = helmetMiddleware;