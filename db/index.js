const { MongoClient } = require('mongodb');
const dotenv = require("dotenv");

const dbConnection = async () => {
    try {
        const client = await new MongoClient(process.env.DB_DEV).connect();
        const db = client.db('week-15');
        
        const booksCollection = db.collection('Books');
        const usersCollection = db.collection('Users'); 
        
        return { db, booksCollection, usersCollection };
    } catch (error) {
        console.log(error, "<=================== error ==================");
        throw new Error("Database connection error");
    }
}

module.exports = dbConnection;

