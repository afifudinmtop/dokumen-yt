const express = require("express");
const mysql = require("mysql");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { engine } = require("express-handlebars");
const app = express();

// Mengatur handlebars sebagai view engine
app.engine("handlebars", engine({ defaultLayout: false }));
app.set("view engine", "handlebars");

// Parse JSON dan form data
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Konfigurasi MySQL
const db = mysql.createConnection({
  host: "localhost",
  user: "tes",
  password: "tes1945",
  database: "tes3",
});

// Konfigurasi session
app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);

// Halaman Register
app.get("/register", (req, res) => {
  res.render("register", { layout: false });
});

// Proses Register
app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = { username: req.body.username, password: hashedPassword };
    const sql = "INSERT INTO coba3 SET ?";
    db.query(sql, user, (error) => {
      if (error) throw error;
      res.redirect("/login");
    });
  } catch {
    res.redirect("/register");
  }
});

// Halaman Login
app.get("/login", (req, res) => {
  res.render("login", { layout: false });
});

// Proses Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const sql = "SELECT * FROM coba3 WHERE username = ?";
  db.query(sql, [username], async (error, results) => {
    if (
      results.length == 0 ||
      !(await bcrypt.compare(password, results[0].password))
    ) {
      res.redirect("/login");
    } else {
      req.session.loggedin = true;
      req.session.username = username;
      res.redirect("/home");
    }
  });
});

// Halaman Home
app.get("/home", (req, res) => {
  if (req.session.loggedin) {
    res.render("home", { username: req.session.username, layout: false });
  } else {
    res.redirect("/login");
  }
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
