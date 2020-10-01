//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const port = 5001;
const app = express();

app.set('view engine', 'ejs');
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
//    cookie: { secure: true }
}));
app.use(passport.initialize());
app.use(passport.session());


app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

mongoose.connect(process.env.DB_CONNECT_STRING, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

mongoose.set("useCreateIndex", true);

let userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User",userSchema);

passport.use(User.createStrategy());

//passport.serializeUser(User.serializeUser());
//passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:"+port+"/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req, res){
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google",{ scope: ["profile"]})
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login",function(req, res){
    res.render("login");
});
app.get("/register",function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
  if (req.isAuthenticated()){
    User.find({secret: {$ne: null}}, function(err, foundUsers){
      if (err){
        console.log(err);
      }else{
        if (foundUsers){
          res.render("secrets", {usersWithSecrets: foundUsers});
        }
      }
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/register",function(req, res){
  User.register({username: req.body.username},
                req.body.password, function(err,user){
                  if (err){
                    console.log(err);
                    res.redirect("/register");
                  } else {
                    passport.authenticate("local")(req, res, function(){
                      res.redirect("/secrets");
                    });
                  }
                });
});

app.get("/submit",function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit",function(req, res){
  const submittedSecret = req.body.secret;
  if (req.user == undefined) {
    res.redirect("/login");
    return;
  }
  console.log(req.user._id);
  User.findById(req.user._id, function(err, foundUser){
    if (err) {
      console.log(err);
    }else{
      if (foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(err){
          if (err) {
            console.log(err);
          }else{
            res.redirect("/secrets");
          }
        });
      }
    }
  });
});

app.listen(port, function(){
  console.log("Server started on port "+port+".");
});
