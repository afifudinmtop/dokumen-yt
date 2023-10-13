const express = require("express");
const mysql = require("mysql");
const app = express();

// Here we're using Express's built-in middleware to parse JSON bodies
app.use(express.json());
// This is for parsing the body of form POST requests
app.use(express.urlencoded({ extended: true }));

// Set up your database connection
const connection = mysql.createConnection({
  host: "localhost", // replace with your database host
  user: "tes",
  password: "tes1945",
  database: "tes3",
});

// Connect to the database
connection.connect((err) => {
  if (err) throw err;
  console.log("Database connected!");
});

// Route that receives the POST request
app.post("/search", (req, res) => {
  const { first_name } = req.body;

  const query = connection.query(
    `SELECT * FROM coba WHERE first_name = '${first_name}'`,
    (error, results) => {
      if (error) {
        console.error("Error executing query:", error);
        res.status(500).send("Internal Server Error");
      } else {
        res.json(results);
      }
    }
  );

  // Log executed query, just for debugging purposes
  console.log(query.sql);
});

// Set the server to listen on a specific port
app.listen(3000, () => {
  console.log("Server is running on port 3000.");
});
