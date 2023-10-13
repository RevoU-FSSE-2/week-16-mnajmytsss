const jwt = require('jsonwebtoken')
const { JWT_SIGN } = require('../config/jwt')

const authenticationMiddleware = (req, res,next) => {
    const authHeader = req.cookies.access_token;

    if(!authHeader) {
        res.status(401).json({error: "unauthorized" })
    } else {
        try {
          if (!JWT_SIGN) {
            throw new Error("JWT_SIGN is not defined");
          }
          const decodedToken = jwt.verify(authHeader, JWT_SIGN);
          console.log("Verified user:", decodedToken);
          next();
        } catch (error) {
        }
    }
}

module.exports = authenticationMiddleware