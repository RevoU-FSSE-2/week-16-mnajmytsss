const { MongoClient } = require('mongodb');
const dotenv = require("dotenv")

const dbConnection = async () => {
    try {
        const client = await new MongoClient(process.env.DB_PROD).connect();
        const db = client.db('week-15');
        const collection = db.collection('Books');
        return { db, collection };
    } catch (error) {
        console.log(error, "<=================== error ==================");
        throw new Error("Database connection error");
    }
}

module.exports = dbConnection;
