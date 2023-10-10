const { Router } = require("express");

const router = Router();

router.get("/", (req, res) => {
    res.send("Hallo ganteng")
});

module.exports = router;