const {Router} = require('express')
const bookController = require('../controller/bookController')
const { 
    authorizationMiddlewareAdmin,
    authorizationMiddlewareManager, 
    authorizationMiddlewareUser,
    authorizationMiddlewareAll
} = require("../middleware/authorizationMiddleware")

const router = Router();

//HTTP Method

//Post Book
router.post('/books', authorizationMiddlewareAll, bookController.createBook)

//Get Book
router.get('/books', authorizationMiddlewareAll, bookController.getAllBook)

//Put Book
router.put('/books/:id', authorizationMiddlewareAll, bookController.updateBook)

//Delete Book
router.delete('/books/:id', authorizationMiddlewareAll, bookController.deleteBook)

module.exports = router;