const { ObjectId } = require('mongodb');
const { JWT_SIGN } = require('../config/jwt');
const { verify } = require('jsonwebtoken');
const jwt = require("jsonwebtoken")

async function createBook(req, res) {
    const { name } = req.body;
    const accessToken = req.cookies.access_token;

    try {
        const decodedToken = jwt.verify(accessToken, JWT_SIGN);
        const currentUser = decodedToken.username;

        const existingBook = await req.booksCollection.findOne({ author: currentUser, name });

        if (existingBook) {
            res.status(409).json({
                message: 'Book already exists for this user.',
                success: false,
            });
            return;
        }

        const newBook = await req.booksCollection.insertOne({
            name,
            author: currentUser,
        });

        res.status(201).json({
            message: 'Successfully added book',
            data: newBook,
            success: true,
        });
    } catch (error) {
        console.error(error);

        res.status(error.status || 500).json({
            message: error.message || 'Internal Server Error',
            success: false,
        });
    }
}


    async function getAllBook(req, res) {
        const accessToken = req.cookies.access_token

        try {
            if (!JWT_SIGN) throw new Error("JWT_SIGN is not defined");

            const accessTokenPayload = verify(accessToken, JWT_SIGN);

            let query = { author: accessTokenPayload.username }

            if (
                accessTokenPayload.role === "admin" ||
                accessTokenPayload.role === "manager"
              ) {
                query = {};
              }

            const books = await req.booksCollection.find(query).toArray();
            if (!books) {
                return ({
                    status: 404,
                    message: "Book list not found",
                    success: false,
                  });
                }
                return res.status(200).json({
                    success: true,
                    message: "Successfully get all books",
                    data: books,
                  });
        } catch (error) {
            throw {
                status: error.status || 500,
                message: error.message || "Internal Server Error",
                success: false,
            }
        }
    }

async function updateBook(req, res) {
    const id = req.params.id;
    const { name } = req.body;
    const token = req.cookies.access_token;

    try {
        const isValidObjectId = ObjectId.isValid(id);

        if (!isValidObjectId) {
            res.status(400).json({
                message: 'Invalid ObjectId in the URL',
                success: false
            });
            return;
        }
        const decodedToken = jwt.verify(token, JWT_SIGN);
        console.log('Decoded Token:', decodedToken);
        const currentUser = decodedToken.username;
        const userRole = decodedToken.role;

        const getBook = await req.booksCollection.findOne({ _id: new ObjectId(id) });

        if (!getBook) {
            res.status(401).json({
                message: "Unauthorized: Book not found or does not belong to the current user."
            });
            return;
        }

        if (userRole === 'user', "manager", "amdin" && getBook.author !== currentUser) {
            res.status(401).json({
                message: "Unauthorized: You are not the author of this book."
            });
            return;
        }

        const updatedBook = await req.booksCollection.updateOne(
            { _id: new ObjectId(id) },
            {
                $set: {
                    name,
                }
            }
        );
        res.status(200).json({
            message: 'Updated',
            data: updatedBook
        });
    } catch (error) {
        console.error(error);
    
        if (error.name === 'JsonWebTokenError') {
            res.status(401).json({
                message: 'Unauthorized: Invalid token',
                success: false
            });
        } else if (error.name === 'TokenExpiredError') {
            res.status(401).json({
                message: 'Unauthorized: Token expired',
                success: false
            });
        } else {
            res.status(500).json({
                message: 'Internal Server Error',
                error: error.message
            });
        }
    }
}

    async function deleteBook(req, res) {
        const { id } = req.params;
        const token = req.cookies.access_token

    try {
        const decodedToken = jwt.verify(token, JWT_SIGN)
        const currentUser = decodedToken.username;
        const userRole = decodedToken.role;

        const getBook = await req.booksCollection.findOne({ _id: new ObjectId(id) })

        if ( !getBook) {
            res.status(401).json({
                message: "Unauthorized: Book not found or does not belong to the current user."
            })
        }

        if (userRole === "user", "manager", "admin" && getBook.author !== currentUser) {
            res.status(401).json({
                message: "Unauthorized: You are not the author of this book."
            });
            return;
        }

        const book = await req.booksCollection.findOneAndUpdate(
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
    } catch (error) {
        console.error(error);
    
        if (error.name === 'JsonWebTokenError') {
            res.status(401).json({
                message: 'Unauthorized: Invalid token',
                success: false
            });
        } else if (error.name === 'TokenExpiredError') {
            res.status(401).json({
                message: 'Unauthorized: Token expired',
                success: false
            });
        } else {
            res.status(500).json({
                message: 'Internal Server Error',
                error: error.message
            });
        }
    }
    }

    module.exports = {
        createBook,
        getAllBook,
        updateBook,
        deleteBook
    }