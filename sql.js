const { pool } = require('./database');
const bcrypt = require('bcrypt');

const SQL_MY = (query, values, res, callback) => {
  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error getting connection from pool:', err);
      res.status(500).json({ error: `Error getting connection: ${err.message}` });
      return;
    }
    
    connection.query(query, values, (queryError, results) => {
      connection.release();
      if (queryError) {
        console.error(`Error executing SQL query: ${query} - ${queryError.message}`);
        res.status(500).json({ error: `Error executing SQL query: ${queryError.message}` });
        return;
      }
      
      callback(results);
    });
  });
};

module.exports = { SQL_MY };
