const { Router } = require("express")
const { register, login, logout, refreshAccessToken } = require("../controller/authController")

const authRouter = Router()

authRouter.post("/register", register)
authRouter.post("/login", login)
authRouter.post("/logout", logout)
authRouter.post("/refresh-token", refreshAccessToken)

module.exports = authRouter