//jshint esversion:6
// bigass app file - To be refactored into modular pattern
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
const baseRoute = "/portfolio/secrets"; // needed to set this route for hosting it on my site
const app = express();

app.set('view engine', 'ejs');
app.set('views', __dirname+'/views');
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
//    cookie: { secure: true }
}));
app.use(passport.initialize());
app.use(passport.session());

// body-parser
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static(__dirname+"/public"));

// connect to mongodb
mongoose.connect(process.env.DB_CONNECT_STRING, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set("useCreateIndex", true);

// user Schema to hold poster of secret
let userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});
//apply passport plugins for user Schema
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User",userSchema);
// creating email/pass strategy
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//creating google strategy upon success find or create user in users collection
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://www.lukapondreeve.com/portfolio/secrets/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
// need to handle this part - it somehow duplicates key
      return cb(err, user);
    });
  }
));

// Routing
app.get("/",function(req, res){
    res.render("home");
});

// OAUTH part
app.get("/auth/google",
  passport.authenticate("google",{ scope: ["profile"]})
);
app.get('/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: baseRoute+'/secrets',
        failureRedirect: baseRoute+'/login',
        scope: [ 'profile' ]
    })
);

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
    res.redirect(baseRoute+"/login");
  }
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect(baseRoute+"/");
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
        res.redirect(baseRoute+"/secrets");
      });
    }
  });
});

app.post("/register",function(req, res){
  User.register({username: req.body.username},
                req.body.password, function(err,user){
                  if (err){
                    console.log(err);
                    res.redirect(baseRoute+"/register");
                  } else {
                    passport.authenticate("local")(req, res, function(){
                      res.redirect(baseRoute+"/secrets");
                    });
                  }
                });
});

// render secret entry view "submit"
app.get("/submit",function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect(baseRoute+"/login");
  }
});

// save secret
app.post("/submit",function(req, res){
  const submittedSecret = req.body.secret;
  if (req.user == undefined) {
    res.redirect(baseRoute+"/login");
    return;
  }
  //console.log(req.user._id);
  User.findById(req.user._id, function(err, foundUser){
    if (err) {
      console.log(err);
    }else{
      if (foundUser){
// basically it doesnt inserts a record. It updates it.. to be fixed
        foundUser.secret = submittedSecret;
        foundUser.save(function(err){
          if (err) {
            console.log(err);
          }else{
            res.redirect(baseRoute+"/secrets");
          }
        });
      }
    }
  });
});

app.listen(port, function(){
  console.log("Server started on port "+port+".");
});
