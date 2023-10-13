const { Router } = require("express");
const bookRoutes = require("./bookRoutes");
const dashboardRoutes = require("./dashboardRoutet");
const preventAttackController = require("./preventAttackRoutes")
const authRouter = require("./authRoutes")
const authenticationMiddleware = require("../middleware/authenticationMiddleware")

const router = Router();

router.use("/", dashboardRoutes);
router.use("/api/v1/attack", preventAttackController)
router.use("/api/v1", authenticationMiddleware, bookRoutes);
router.use("/auth", authRouter)


module.exports = router;