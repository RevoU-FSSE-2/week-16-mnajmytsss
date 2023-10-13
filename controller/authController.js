const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const JWT_SIGN = require('../config/jwt')
const NodeCache = require('node-cache')
const { addDays } = require("date-fns");
const nodemailer = require("nodemailer")

const validRoles = ["user", "admin", "manager"];
const failedLoginAttemptsCache = new NodeCache({ stdTTL: 600 });

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
  

  const refreshAccessToken = async (req, res) => {
    try {
        const { refresh_token } = req.cookies;

        if (!refresh_token) {
            throw new Error('Refresh token not provided');
        }

        const JWT_SIGN = process.env.JWT_SIGN;

        if (!JWT_SIGN) {
            throw new Error('JWT_SIGN is not defined');
        }

        const decoded = jwt.verify(refresh_token, JWT_SIGN);

        const { username, id, role } = decoded;

        const accessToken = jwt.sign(
            { username, id, role },
            JWT_SIGN,
            { expiresIn: '10m' }
        );

        res.cookie('access_token', accessToken, {
            maxAge: 10 * 60 * 1000,
            httpOnly: true,
        });

        return res.status(200).json({
            success: true,
            message: {
                accessToken,
            },
        });
    } catch (error) {
        res.status(401).json({ success: false, error: 'Invalid refresh token' });
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

  const requestResetPassword = async (req, res) => {
    try {
      const { email } = req.body;
  
      const user = await usersCollection.findOne({ email });
  
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found.',
        });
      }
  
      const resetToken = await bcrypt.hash(user.email, 10);
  
      const expiredAt = new Date();
      expiredAt.setHours(expiredAt.getHours() + 1);
  
      await PasswordReset.create({
        email: user.email,
        token: resetToken,
        expiredAt,
      });
  
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'your-email@gmail.com',
          pass: 'your-email-password',
        },
      });
  
      const resetLink = `http://your-frontend-url/reset-password/${resetToken}`;
  
      const mailOptions = {
        from: 'your-email@gmail.com',
        to: user.email,
        subject: 'Reset Password',
        html: `<p>Click the link to reset your password: ${resetLink}</p>`,
      };
  
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error(error);
          return res.status(500).json({
            success: false,
            message: 'Failed to send reset password email.',
          });
        } else {
          console.log('Email sent: ' + info.response);
          return res.status(200).json({
            success: true,
            message: 'Password reset request has been sent. Please check your email.',
          });
        }
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        success: false,
        message: 'Internal server error.',
      });
    }
  };

module.exports = {
    register,
    login,
    refreshAccessToken,
    requestResetPassword,
    logout
}
