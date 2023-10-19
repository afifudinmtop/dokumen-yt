const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const path = require("path");
const app = express();

app.use(express.json());

// Konfigurasi koneksi ke database
const db = mysql.createConnection({
  host: "localhost",
  user: "tes",
  password: "tes1945",
  database: "tes3",
});

// Membuka koneksi ke MySQL
db.connect((err) => {
  if (err) throw err;
  console.log("Connected to the database.");
});

// Endpoint untuk registrasi
app.post("/register", async (req, res) => {
  try {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    const user = { username: req.body.username, password: hashedPassword };
    const sql = "INSERT INTO coba2 SET ?";
    db.query(sql, user, (err, result) => {
      if (err) throw err;
      res.status(201).send("User created");
    });
  } catch {
    res.status(500).send();
  }
});

// Endpoint untuk login
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const sql = "SELECT * FROM coba2 WHERE username = ?";
  db.query(sql, username, async (err, results) => {
    if (err) throw err;

    if (results.length > 0) {
      const user = results[0];
      if (await bcrypt.compare(password, user.password)) {
        res.send("Success");
      } else {
        res.status(400).send("Not Allowed");
      }
    } else {
      res.status(400).send("User not found");
    }
  });
});

// Routing untuk halaman register dan login
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "register.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

// Menjalankan server
app.listen(3000, () => {
  console.log("Server is running on port 3000.");
});
