const dbConnection = require('../db');

const databaseMiddleware = async (req, res, next) => {
    const { db, booksCollection, usersCollection } = await dbConnection();
    req.db = db;
    req.booksCollection = booksCollection; // Updated to include Books collection
    req.usersCollection = usersCollection; // Added Users collection
    next();
};

module.exports = databaseMiddleware;

