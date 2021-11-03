const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const app = express();
const session = require("express-session");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
require('dotenv').config()
app.use(
  cors({
    origin: [process.env.API_URL],
    credentials: true,
    methods: ["POST", "GET", "PUT", "DELETE"],
  })
);
app.use(cookieParser())
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SEESION_SECRETE,
    resave: true,
    saveUninitialized: false,
    cookie: { 
      httpOnly:true,
      // secure: true ,
      maxAge:parseInt(process.env.MAXAGE)
    },
  })
);

dbConfig = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database:process.env.DB_NAME,
});

app.get("/", (req, res) => {
  res.send("hello api");
});

app.get("/v1/login",(req,res)=>{
  if(req.session.token){
    res.send({
      error: false,
      message: "success",
      // token: token,
      token:req.session.token
    });
  }else{
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
      res.send(error);
    } else {
      if (result) {
        console.log(result);
        res.send({
          error: false,
          message: "success",
        });
      } else {
        res.send({
          error: true,
          message: "something went wrong",
        });
      }
    }
  });
});

const varifytoken = (req, res, next) => {
  const token = req.header["token"];
  if (!token) {
    res.send({
      error: true,
      message: "token not send",
    });
  } else {
    jwt.verify(token, "riotechio", (err, decode) => {
      if (err) {
        res.send({
          error: true,
          message: " invalid token send",
        });
      }else{
        console.log(decode);
        req.token=decode.id;
        next();

      }
    });
  }
};

app.get("/v1/user", varifytoken, (req, res) => {
res.send()

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
        // console.log(result);
        // req.session.user=result[0];
        //  req.session.user=result[0];
        const uid = result[0].id;
        // for security u can use .env file to store sensitive info
        const token = jwt.sign({ uid }, "riotechio", {
          expiresIn: "2h",
        });
        req.session.token=token;
        res.send({
          error: false,
          message: "success",
          token: token,
          // session:req.session.user
        });
      }
    }
  });
});

app.listen(9000, () => {
  console.log("am working");
});
