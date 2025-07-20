const app = require('./src/app');
const dotenv = require('dotenv');
dotenv.config();

const db = require('./src/config/dbConfig');

const PORT = process.env.PORT || 5000;

db.connect()
  .then(() => {
    console.log('Connected to the database');
    // app.listen(PORT, () => {
    //   console.log(`Server is running on port ${PORT}`);
    // });
  })
  .catch(err => {
    console.error('Database connection error:', err);
  });