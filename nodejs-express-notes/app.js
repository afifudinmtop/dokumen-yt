const express = require("express");
const path = require("path");
const app = express();
const port = 3000;
const { engine } = require("express-handlebars");

// path root
const root_dir = require("./util/path");

// template engine
app.engine("handlebars", engine({ defaultLayout: "main" }));
app.set("view engine", "handlebars");

// body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// serve static files
app.use("/assets", express.static(path.join(root_dir, "public")));

// routes
const routes_dashboard = require("./routes/dashboard");
const routes_notes = require("./routes/notes");
const routes_databases = require("./databases/api");

app.use(routes_dashboard);
app.use("/notes", routes_notes);
app.use("/databases", routes_databases.routes);

// 404
app.use((req, res, next) => {
  res.status(404).sendFile(path.join(root_dir, "views", "404.html"));
});

// log
app.listen(port, () => {
  console.log(`Note app listening on port ${port}`);
});
