const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { JWT_SIGN } = require('../config/jwt');
const NodeCache = require('node-cache')
const { addDays } = require("date-fns");
const { v4: uuidv4 } = require('uuid');

const validRoles = ["user", "admin", "manager"];
const failedLoginAttemptsCache = new NodeCache({ stdTTL: 600 });
const cacheKey = new NodeCache({ stdTTL: 300 });

const register = async (req, res) => {
    try {
        const { username, password, role } = req.body;

        const userCollection = req.usersCollection;

        if (username.trim() === '') {
            throw new Error('Username cannot be blank');
        }

        if (!validRoles.includes(role)) {
            throw new Error('Invalid role');
        }

        const existingUser = await userCollection.findOne({ username });
        if (existingUser) {
            throw new Error('Username is already taken');
        }

        if (!password.match(/^(?=.*[a-zA-Z])(?=.*\d).{8,}$/)) {
            throw new Error(
                'Password must be alphanumeric and at least 8 characters long'
            );
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await userCollection.insertOne({
            username,
            password: hashedPassword,
            role,
        });

        res.status(200).json({
            success: true,
            message: 'User successfully registered',
            data: { _id: newUser.insertedId },
        });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
};

const login = async (req, res, next) => {
    
      const { usersCollection } = req;
      const { username, password } = req.body;
  
      
      const loginAttempts = failedLoginAttemptsCache.get(username) || 1;
      console.log(loginAttempts, "failed login attemps");

      if (loginAttempts >= 5) {
        return res.status(429).json({
          success: false,
          message: "Too many failed login attempts. Please try again later.",
        });
      }
  
    try {
      const user = await usersCollection.findOne({ username });
      if (!user) {
        failedLoginAttemptsCache.set(username, loginAttempts + 1);
        throw ({
          success: false,
          message: "Incorrect username or password. Please try again.",
          status: 401,
        });
      } 
  
      const isPasswordCorrect = await bcrypt.compare(password, user.password);
  
      if (isPasswordCorrect) {  
        const JWT_SIGN = process.env.JWT_SIGN;
  
        if (!JWT_SIGN) throw new Error("JWT_SIGN is not defined");
  
        const accessTokenExpiration = addDays(new Date(), 300);
        const accessToken = jwt.sign(
          { username: user.username, id: user._id, role: user.role },
          JWT_SIGN,
          { expiresIn: "5m" }
        );
        const refreshTokenPayload = {
          username: user.username,
          id: user._id,
          role: user.role,
        };
        const refreshToken = jwt.sign(refreshTokenPayload, JWT_SIGN, {
          expiresIn: "5d",
        });

        failedLoginAttemptsCache.del(username);
  
        res.cookie("access_token", accessToken, {
          maxAge: 5 * 60 * 1000,
          httpOnly: true,
        });
        res.cookie("refresh_token", refreshToken, {
          maxAge: 5 * 24 * 60 * 60 * 1000, 
          httpOnly: true,
        });
  
        return res.status(200).json({
          success: true,
          message: {
            accessToken,
            refreshToken,
            accessTokenExpiration,
          },
        });
      } else {
        failedLoginAttemptsCache.set(username, loginAttempts + 1);
        throw ({
          success: false,
          message: "Incorrect username or password. Please try again.",
          status: 401,
        });
      }
    } catch (error) {
        console.log(error);
    
        if (error.status === 401) {
          return res.status(401).json({
            success: false,
            message: error.message,
          });
        } else {
          return res.status(500).json({
            success: false,
            message: "Internal server error",
          });
        }
    }

  };
  

const refreshAccessToken = async (req, res, next) => {
    const refreshToken = req.cookies.refresh_token;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: "refresh token is missing"
      })
    }

    if (!JWT_SIGN) throw new Error('JWT_SIGN is not defined')
      const decodedRefreshToken = jwt.verify(refreshToken, JWT_SIGN);
    console.log(decodedRefreshToken);

    try {
      if (
        !decodedRefreshToken || !decodedRefreshToken.exp 
      ) {
        throw {
          success: false,
          status: 401,
          message: 'Refresh token is invalid or has expired. Please login again',
        }
      }

      if (decodedRefreshToken.exp < Date.now() / 1000) {
        throw {
          success: false,
          status: 401,
          message: "Refresh token has expired. Please login again"
        }
      }

      if (refreshToken) {
      const accessToken = jwt.sign(decodedRefreshToken, JWT_SIGN)

      res.cookie("access_token", accessToken, {
        maxAge: 10 * 60 * 1000,
        httpOnly: true,
      })

      return res.status(200).json({
        success: true,
        message: "access token refresh successfully",
        data: { accessToken }
      })
    }
    } catch (error) {
      next(error)
    }
};

const logout = async (req, res, next) => {
    try {
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");
      return res.status(200).json({
        success: true,
        message: "Successfully logout",
      });
    } catch (error) {
      next(error);
    }
  };

  const requestResetPassword = async (req, res, next) => {
    const { username } = req.body;

    try {
      const user = await req.usersCollection.findOne({ username });

      if (!user) {
        throw {
          status: 404,
          message: "User not found.",
          success: false,
        }
      } 
      const tokenResetPassword = uuidv4();

      cacheKey.set(tokenResetPassword, username, 900);
      return res.status(200).json({
        success: true,
        message: "reset password link has been sent",
        data: tokenResetPassword,
      })
    } catch (error) {
      console.log(error);
      res.status(500).json({
        success: false,
        message: error.message || 'Internal Server Error',
      });
    }
  };

  const resetPassword = async (req, res, next) => {
    const { newPassword } = req.body;
    const { token } = req.query;
    console.log('Request Query:', req.query);
    console.log('Request Body:', req.body);


    try {
      if (!token || typeof token !== 'string') {
        throw ('Token is not a string.');
    }

      const username = cacheKey.get(token);
      console.log('Username retrieved from cache:', username);

      if(!username) {
        throw {
          success: false,
          status: 401,
          message: "invalid or expired token",
        }
      }

      const user = await req.usersCollection.findOne({ username });

      if (!user) {
      res.status(400).json({ error: "User not found" });
      return;
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);

      await req.usersCollection.findOneAndUpdate({ username }, { $set: { password: hashedPassword } });

      cacheKey.del(token);

      return res.status(200).json({
        success: true,
        message: "password reset successfully",
      });

    } catch (error) {
      console.error(error);
      next(error)
    }
  }

module.exports = {
    register,
    login,
    refreshAccessToken,
    requestResetPassword,
    resetPassword,
    logout
}
