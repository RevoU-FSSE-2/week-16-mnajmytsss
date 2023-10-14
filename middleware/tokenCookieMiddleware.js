async function tokenCookieMiddleware (req, res, next) {
    const accessTokenCookie = req.cookies['accessToken'];
    const refreshTokenCookie = req.cookies['refreshToken'];
  
    if (!accessTokenCookie && refreshTokenCookie) {
      res.status(401).json({
        message: 'Access token expired, hit refresh token endpoint to re-generate Access token'
      });
    } else if (accessTokenCookie) {
      next();
      return;
    } else {
      res.status(403).json({
        message: 'Please login to consume API'
      });
      return;
    }
  }

module.exports = tokenCookieMiddleware
  