// ⚠️ TP10 : application VOLONTAIREMENT vulnérable. Ne jamais l'exposer hors du lab.
// Chaque bloc marqué [VULN] doit être détecté par un outil puis corrigé.
const express = require("express");
const { exec } = require("child_process");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const _ = require("lodash");
const config = require("./config");

const app = express();
app.use(express.json());

const db = new sqlite3.Database(":memory:");
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)");
  db.run("INSERT INTO users (name, role) VALUES ('alice', 'admin'), ('bob', 'user')");
});

// [VULN] Injection SQL : la valeur de l'utilisateur est concaténée dans la requête.
app.get("/users", (req, res) => {
  const sql = "SELECT id, name FROM users WHERE name = '" + req.query.name + "'";
  db.all(sql, (err, rows) => (err ? res.status(500).send(err.message) : res.json(rows)));
});

// [VULN] Injection de commande : l'entrée est passée à un shell.
app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, stdout) => res.type("text").send(stdout || String(err)));
});

// [VULN] XSS réfléchi : l'entrée est renvoyée dans du HTML sans échappement.
app.get("/hello", (req, res) => {
  res.send("<h1>Bonjour " + req.query.name + "</h1>");
});

// [VULN] Prototype pollution via une version vulnérable de lodash (merge récursif d'un objet client).
app.post("/settings", (req, res) => {
  const settings = _.merge({}, req.body);
  res.json(settings);
});

// [VULN] Jeton signé avec un secret codé en dur, sans expiration.
app.post("/login", (req, res) => {
  const token = jwt.sign({ user: req.body.user, role: "user" }, config.jwt_secret);
  res.json({ token });
});

app.listen(config.port, () => console.log(`vuln-app écoute sur ${config.port}`));
