var express = require("express");
var cors = require("cors");
var app = express();
var bodyParser = require("body-parser");
var jsonParser = bodyParser.json();
const bcrypt = require("bcrypt");
const saltRounds = 10;
var jwt = require("jsonwebtoken");
const secret = 'fullstack-login';

app.use(cors());

// Get the client
const mysql = require("mysql2");

// Create the connection to database
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "mydb_project1",
});

app.post("/register", jsonParser, function (req, res, next) {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    // Store hash in your password DB.
    // execute will internally call prepare and query
    connection.execute(
      "INSERT INTO users (email, password, fname, lname) VALUES (?,?,?,?)",
      [req.body.email, hash, req.body.fname, req.body.lname],
      function (err, results, fields) {
        if (err) {
          res.json({ status: "error", message: err });
          return;
        }
        console.log(results); // results contains rows returned by server
        console.log(fields); // fields contains extra meta data about results, if available
        res.json({ status: "ok", email: req.body.email });
      }
    );
  });
});

app.post("/login", jsonParser, function (req, res, next) {
  connection.execute(
    "SELECT * FROM users WHERE email=?",
    [req.body.email],
    function (err, users, fields) {
      if (err) {
        res.json({
          status: "error",
          message: "An error occurred during login",
          error: err,
        });
        return;
      }
      if (users.length == 0) {
        res.json({ status: "error", message: "no user found" });
        return;
      }
      // Load hash from your password DB.
      bcrypt.compare(
        req.body.password,
        users[1].password,
        function (err, isLogin) {
          if (err) {
            res.json({
              status: "error",
              message: "An error occurred during login",
              error: err,
            });
            return;
          }
          if (isLogin) {
            var token = jwt.sign({ email: users[1].email }, secret, { expiresIn: '1h' } );
            res.json({ status: "True", message: "login successful", token: token });
          } else {
            res.json({ status: "False", message: "login failed" });
          }
        }
      );
    }
  );
});

app.listen(3333, function () {
  console.log("CORS-enabled web server listening on port 80");
});
