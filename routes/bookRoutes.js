const {Router} = require('express')
const bookController = require('../controller/bookController')

const router = Router();

//HTTP Method

//Post Book
router.post('/', bookController.createBook)

//Get Book
router.get('/', bookController.getAllBook)

//Put Book
router.put('/:id', bookController.updateBook)

//Delete Book
router.delete('/:id', bookController.deleteBook)

module.exports = router;