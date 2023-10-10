const dbConnection = require('../db');

const databaseMiddleware = async (req, res, next) => {
 const { db, collection } = await dbConnection();
req.db = db;
req.collection = collection; 
next();
};

module.exports = databaseMiddleware;

