const express = require('express')
const dotenv = require ('dotenv')
const useMiddleware = require('./middleware');
const router = require('./routes');
const tokenCookieMiddleware = require('./middleware/tokenCookieMiddleware')

const app = express()
dotenv.config()

useMiddleware(app)

app.use(router)
app.use(tokenCookieMiddleware)

const port = (process.env.PORT) 

app.listen(port, () => {
 console.log(`Running on port http://localhost:${port}`);
})