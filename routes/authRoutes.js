const { Router } = require("express")
const { register, login, logout, refreshAccessToken, requestResetPassword, resetPassword } = require("../controller/authController")

const authRouter = Router()

authRouter.post("/register", register)
authRouter.post("/login", login)
authRouter.post("/logout", logout)
authRouter.post("/refresh-token", refreshAccessToken)
authRouter.post("/reset-password/request", requestResetPassword)
authRouter.post("/reset-password", resetPassword)

module.exports = authRouter