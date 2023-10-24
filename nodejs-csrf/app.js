const express = require("express");
const { engine } = require("express-handlebars");
const cookieParser = require("cookie-parser");
const csrf = require("csurf");

const app = express();

// Pengaturan middleware
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(csrf({ cookie: true }));

// Pengaturan view engine ke Handlebars
app.engine("handlebars", engine({ defaultLayout: false }));
app.set("view engine", "handlebars");

// Rute untuk menampilkan form, dengan token CSRF
app.get("/form", (req, res) => {
  res.render("form", { csrfToken: req.csrfToken() });
});

// Rute POST untuk menangani pengiriman form
app.post("/submit", (req, res) => {
  res.send("Form submitted successfully.");
});

// Handler error CSRF
app.use((err, req, res, next) => {
  if (err.code !== "EBADCSRFTOKEN") return next(err);

  // jika request tidak memiliki token CSRF yang valid, kita akan memberi respons 403 forbidden
  res.status(403);
  res.send("Session has expired or the form is invalid.");
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
