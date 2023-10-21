const express = require("express");
const { engine } = require("express-handlebars");
const app = express();

app.engine("handlebars", engine({ defaultLayout: "main" }));
app.set("view engine", "handlebars");

app.get("/", (req, res) => {
  const context = {
    title: "Home Page", // variabel biasa
    isAuthorized: false, // untuk kondisi if
    items: [
      // untuk looping each
      { name: "item1" },
      { name: "item2" },
      { name: "item3" },
    ],
    description: "This is a <strong>description</strong>.", // untuk HTML escaping
  };
  res.render("home", context);
});

app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});
