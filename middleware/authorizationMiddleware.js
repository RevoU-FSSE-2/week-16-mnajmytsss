const jwt = require('jsonwebtoken')
const { JWT_SIGN } = require('../config/jwt')

const authorizationMiddlewareAll = (req, res, next) => {
    const authHeader = req.cookies.access_token;

    if(!authHeader) {
        res.status(401).json({error: "unauthorized"})
    } else {
        try {
            if (!JWT_SIGN) {
                throw new Error("JWT_SIGN is not defined");
              }
            const decodedToken = jwt.verify(authHeader, JWT_SIGN)
            if(decodedToken.role === 'admin' || decodedToken.role === 'user' || decodedToken.role === 'manager') {
                next()
            } else {
                res.status(401).json({error: "Unauthorized"})
            }
        } catch (error) {
            res.status(400).json({error: error.message})
        }
    }
}

const authorizationMiddlewareAdmin = (req, res, next) => {
    const authHeader = req.cookies.access_token;

    if(!authHeader) {
        res.status(401).json({error: "Unauthorized"})
    } else {
        try {
             if (!JWT_SIGN) {
                throw new Error("JWT_SIGN is not defined");
              }
            const decodedToken = jwt.verify(authHeader, JWT_SIGN)
            if(decodedToken.role === 'admin') {
                next()
            } else {
                res.status(401).json({error: "Unauthorized"})
            }
        } catch (error) {
            res.status(400).json({error: error.message})
        }
    }
}

const authorizationMiddlewareUser = (req, res, next) => {
    const authHeader = req.cookies.access_token;

    if(!authHeader) {
        res.status(401).json({error: "Unauthorized"})
    } else {
        try {
            if (!JWT_SIGN) {
                throw new Error("JWT_SIGN is not defined");
              }
            const decodedToken = jwt.verify(authHeader, JWT_SIGN)
            if(decodedToken.role === 'user') {
                next()
            } else {
                res.status(401).json({error: "Unauthorized"})
            }
        } catch (error) {
            res.status(400).json({error: error.message})
        }
    }
}

const authorizationMiddlewareManager = (req, res, next) => {
    const authHeader = req.cookies.access_token; 

    if(!authHeader) {
        res.status(401).json({error: "Unauthorized"})
    } else {
        try {
            if (!JWT_SIGN) {
                throw new Error("JWT_SIGN is not defined");
              }
            const decodedToken = jwt.verify(authHeader, JWT_SIGN)
            if(decodedToken.role === 'manager') {
                next()
            } else {
                res.status(401).json({error: 'Unauthorized'})
            }
        } catch (error) {
            res.status(400).json({error: error.message})
        }
    }
}

module.exports = {
    authorizationMiddlewareAll,
    authorizationMiddlewareAdmin,
    authorizationMiddlewareUser,
    authorizationMiddlewareManager
}