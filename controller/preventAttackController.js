async function getDataXss (req, res, next) {
    const {name} = req.query;
    try {
        const data = 'bukan untuk umum'
        res.send(`hello ${name}`)
    } catch (error) {
        next (error)
    }
}

async function getClickJacking(req, res, next) {
    try {
        res.send(`
        <form action="/click-jacking" method="post">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username"><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password"><br>
            <input type="submit" value="Submit">
        </form>
        `)
    } catch (error) {
        next(error)
    }
}

async function createClickJacking(req, res, next) {
    try {
        let username = req.body.username;
        let password = req.body.password;
        res.json({ username: username, password: password})
    } catch {error}
    next(error)
}

module.exports = {
    getDataXss,
    getClickJacking,
    createClickJacking,
}