const express = require("express");
const router = express.Router();
const routes_databases = require("../databases/api");

let notes = routes_databases.notes;

router.get("/list", (req, res, next) => {
  const context = {
    title: "List Notes",
    notes,
  };
  res.render("list", context);
});

router.get("/create", (req, res, next) => {
  const context = {
    title: "Create Notes",
  };
  res.render("create", context);
});

router.get("/edit/:uuid", (req, res, next) => {
  const uuid = req.params.uuid;
  const context = {
    title: "Edit Notes",
    judul: notes[uuid].judul,
    isi: notes[uuid].isi,
    uuid: notes[uuid].uuid,
  };
  res.render("edit", context);
});

module.exports = router;
