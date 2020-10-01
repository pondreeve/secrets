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
const baseRoute = "/portfolio/secrets";
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


app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static(__dirname+"/public"));
console.log(__dirname);

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
    callbackURL: "http://localhost:"+port+baseRoute+"/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get(baseRoute+"/",function(req, res){
    res.render("home");
});

app.get(baseRoute+"/auth/google",
  passport.authenticate("google",{ scope: ["profile"]})
);

app.get( baseRoute+'/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: baseRoute+'/secrets',
        failureRedirect: baseRoute+'/auth/google/failure',
         scope: [ 'https://www.googleapis.com/auth/plus.login' ]

    })
    // , function(req,res){
    //       res.redirect("secrets")
    //     }
);

// app.get(baseRoute+"/auth/google/secrets",
//   passport.authenticate("google", { failureRedirect: baseRoute+"/login" }),
//   function(req, res) {
//     // Successful authentication, redirect home.
//     res.redirect("secrets");
//   });

app.get(baseRoute+"/login",function(req, res){
    res.render("login");
});
app.get(baseRoute+"/register",function(req, res){
    res.render("register");
});

app.get(baseRoute+"/secrets", function(req, res){
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

app.get(baseRoute+"/logout", function(req, res){
  req.logout();
  res.redirect(baseRoute+"/");
});

app.post(baseRoute+"/login", function(req, res){
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

app.post(baseRoute+"/register",function(req, res){
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

app.get(baseRoute+"/submit",function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect(baseRoute+"/login");
  }
});

app.post(baseRoute+"/submit",function(req, res){
  const submittedSecret = req.body.secret;
  if (req.user == undefined) {
    res.redirect(baseRoute+"/login");
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
