// TP10 : version corrigée (SAST)
const express = require("express");
const { execFile } = require("child_process");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const _ = require("lodash");
const escapeHtml = require("escape-html");
const config = require("./config");

const app = express();
app.use(express.json());

const db = new sqlite3.Database(":memory:");
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)");
  db.run("INSERT INTO users (name, role) VALUES ('alice', 'admin'), ('bob', 'user')");
});

// Requête paramétrée : l'entrée ne peut plus modifier le SQL.
app.get("/users", (req, res) => {
  db.all("SELECT id, name FROM users WHERE name = ?", [req.query.name], (err, rows) =>
    err ? res.status(500).send("Erreur") : res.json(rows)
  );
});

// Validation du host + execFile : aucun shell n'interprète l'entrée.
app.get("/ping", (req, res) => {
  const host = String(req.query.host || "");
  if (!/^[a-zA-Z0-9.-]{1,253}$/.test(host)) return res.status(400).send("host invalide");
  execFile("ping", ["-c", "1", host], (err, stdout) => res.type("text").send(stdout || "échec"));
});

// Échappement HTML de l'entrée utilisateur.
app.get("/hello", (req, res) => {
  res.send("<h1>Bonjour " + escapeHtml(String(req.query.name || "")) + "</h1>");
});

// lodash sera mis à jour dans la partie 4 (prototype pollution).
app.post("/settings", (req, res) => {
  const settings = _.merge({}, req.body);
  res.json(settings);
});

// Secret depuis l'environnement + expiration du jeton.
app.post("/login", (req, res) => {
  const token = jwt.sign({ user: req.body.user, role: "user" }, config.jwt_secret, { expiresIn: "1h" });
  res.json({ token });
});

app.listen(config.port, () => console.log(`vuln-app écoute sur ${config.port}`));
