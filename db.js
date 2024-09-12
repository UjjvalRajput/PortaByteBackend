const mongoose = require('mongoose'); // import mongoose
require('dotenv').config(); // import dotenv

const MONGO_URL = process.env.MONGO_URL; // get mongo url from env
const DB_NAME = process.env.DB_NAME; // get db name from env

mongoose.connect(MONGO_URL, {
    dbName: DB_NAME
}).then(
    () => {
        console.log('Connected to database'); // log message
    }
).catch((err) => {
    console.log('Error connecting to database', err); // log error
});
