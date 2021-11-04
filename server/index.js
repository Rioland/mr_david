const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const app = express();
const session = require("express-session");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
require("dotenv").config();
app.use(
  cors({
    origin: [process.env.API_URL],
    credentials: true,
    methods: ["POST", "GET", "PUT", "DELETE"],
  })
);
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SEESION_SECRETE,
    resave: true,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      // secure: true ,
      maxAge: parseInt(process.env.MAXAGE),
    },
  })
);

dbConfig = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

app.get("/", (req, res) => {
  res.send("hello api");
});

app.get("/v1/login", (req, res) => {
  if (req.session.token) {
    res.send({
      error: false,
      message: "success",
      // token: token,
      token: req.session.token,
    });
  } else {
    res.send({
      error: true,
      message: "not login",
    });
  }
});

app.post("/v1/register", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const name = req.body.name;
  const phone = req.body.phoneNumber;
  //  password bcrypt hash
  // ---------

  // goes here

  const q =
    "INSERT INTO users (username, phone, password,name) VALUES (?,?,?,?);";
  dbConfig.query(q, [username, phone, password, name], (error, result) => {
    if (error) {
      res.send({
        error: true,
        message: error,
      });
    } else {
      console.log(result);
      res.send({
        error: false,
        message: "success",
      });
    }
  });
});
// format bearer <token>
const varifytoken = (req, res, next) => {
  const bearerHeader = req.headers["authorization"];
  if (typeof bearerHeader == "undefined") {
    res.send({
      error: true,
      message: "token not send",
    });
  } else {
    const bearer = bearerHeader.split(" ");
    const token = bearer[1];
    req.token = token;
    next();
  }
};

app.get("/v1/profile", varifytoken, (req, res) => {
  jwt.verify(req.token, process.env.JWT_SECRITE, (err, tokenpayload) => {
    if (err) {
      res.send({
        error: true,
        message: err,
      });
    } else {
      console.log(tokenpayload);
      res.json({
        error: false,
        message: "success",
        data: tokenpayload,
      });
    }
  });
});

app.post("/v1/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  //  password bcrypt hash
  // ---------

  // goes here

  const q = "SELECT * FROM users WHERE username=? and password=?";
  dbConfig.query(q, [username, password], (err, result) => {
    if (err) {
      res.send(err);
    } else {
      if (result == "") {
        res.send({
          error: true,
          message: "invalid details",
        });
      } else {
        //  console.log(process.env.JWT_SECRITE)
        const user = result[0];
        const token = jwt.sign({ user }, process.env.JWT_SECRITE, {
          expiresIn: "3h",
        });
        if (token) {
          req.session.token = token;
          res.send({
            error: false,
            message: "success",
            token: token,
          });
        } else {
          res.json({
            error: true,
            message: "can not generate token",
          });
        }
      }
    }
  });
});

app.get("/v1/allusers", varifytoken, (req, res) => {
  jwt.verify(req.token, process.env.JWT_SECRITE, (err, payload) => {
    if (err) {
      res.send({
        error: true,
        message: err,
      });
    } else {
      dbConfig.query("select * from users", (err, result) => {
        if (err) {
          res.send({
            error: true,
            message: "server error",
          });
        } else {
          res.send({
            error: false,
            message: "success",
            data: result,
          });
        }
      });
      // console.log(payload);
      // res.json({
      //   error: true,
      //   message: " invalid token send",
      //   data:tokenpayload
      // });
    }
  });
});

app.listen(9000, () => {
  console.log("am working");
});
