require('dotenv').config()
const express = require("express")
const _ = require("lodash")
const ejs = require("ejs")
const bodyParser = require("body-parser")
const mongoose = require("mongoose")
const encrypt = require("mongoose-encryption")
const md5 = require("md5")
const bcrypt = require("bcrypt")
const saltRounds = 10
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const findOrCreate = require("mongoose-findorcreate")

const app = express()

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}))
app.set("view engine","ejs");

const port = process.env.port || 3000

app.use(session({
    secret: "OurfirstmanDiesontheMoon",
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb://localhost:27017/userDB")

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleID: String,
    secret: String
})

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

const User = mongoose.model("User", userSchema)

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        // picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    passReqToCallback   : true
  },
  function(request, accessToken, refreshToken, profile, done) {
    console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));



app.get("/",(req,res)=>{
    res.render("home");
})

app.get("/auth/google",passport.authenticate("google", {scope:["profile"]}))

app.get( "/auth/google/secrets",
    passport.authenticate( "google", {
        successRedirect: "/secrets",
        failureRedirect: "/login"
}));

app.get("/login",(req,res)=>{
    res.render("login");
})

app.get("/register",(req,res)=>{
    res.render("register");
})

app.get("/secrets",(req,res)=>{
    User.find({"secret": {$ne:null}}, (err,foundUsers)=>{
        if(err){
            console.log(err)
        } else {
            res.render("secrets",{usersWithSecret: foundUsers})
        }
    })
})

app.get("/submit", (req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit")
    }else{
        res.redirect("/login")
    }
})

app.get("/logout",(req,res)=>{
    req.logout(()=>{
        res.redirect("/")
    })
})

app.post("/submit",(req,res)=>{
    const submitedSecret = req.body.secret;

    User.findById(req.user.id, function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submitedSecret
                foundUser.save(()=>{
                    res.redirect("/secrets")
                })
            }
        }
    })
})

app.post("/register",(req,res)=>{
    User.register({username: req.body.username},req.body.password,(err,user)=>{
        if(err){
            console.log(err)
            res.redirect("/register")
        }else{
            passport.authenticate("local")(req,res,()=>{
                res.redirect("/secrets")
            })
        }
    })
})

app.post("/login",(req,res)=>{
    const user = new User({
        username: req.body.username,
        password: req.body.password
 })
    req.login(user,function (err) {
        if(err){
            console.log(err)
        }else{
            passport.authenticate("local")(req,res,()=>{
                res.redirect("/secrets")
            })
        }
    })  
})

app.listen(port,()=>{
    console.log("App is listening on " + port)
})