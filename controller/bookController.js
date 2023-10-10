const { ObjectId } = require('mongodb');

async function createBook(req, res) {
    const { name, author } = req.body;

    const book = await req.collection.insertOne({
        name,
        author,
    });

    res.status(200).json({
        message: 'successfully add book',
        data: book
    });
}

async function getAllBook(req, res) {
    const books = await req
    .collection
    .find({ is_deleted: {$exists: false}})
    .toArray();

    res.status(200).json({
        message: 'success',
        data: books
    })
}

async function updateBook(req, res) {
    const id = req.params.id;
    const {name, author} = req.body;

    const book = await req.collection.updateOne(
        { _id: new ObjectId(id) },
        {
            $set: {
                name, 
                author
            }
        }
    );

    res.status(200).json({
        message: 'updated',
        data: book
    })
}

async function deleteBook(req, res) {
    const { id } = req.params;
    const book = await req.collection.findOneAndUpdate(
        { _id: new ObjectId(id)},
        {
            $set: {
                is_deleted: true,
            }
        }
    );

    res.status(200).json({
        message: "successfully deleted"
    })
}

module.exports = {
    createBook,
    getAllBook,
    updateBook,
    deleteBook
}