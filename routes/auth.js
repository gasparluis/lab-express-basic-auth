const express = require("express");
const router = express.Router();
const User = require("../models/User.model");
const bcrypt = require("bcryptjs");

router.get("/signup", (req, res) => {
  res.render("auth/signup");
});

router.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  //check if username and password are filled in
  if (username === "" || password === "") {
    res.render("auth/signup", { errorMessage: "Fill username and password" });
    return;
  }

  //check for password strength
  const myRegex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (myRegex.test(password) === false) {
    res.render("auth/signup", {
      errorMessage: "Password is too weak",
    });
    return;
  }

  //check if username already exists
  const user = await User.findOne({ username });
  if (user !== null) {
    res.render("auth/signup", { errorMessage: "Username already exists" });
    return;
  }

  const saltRounds = 10;
  const salt = bcrypt.genSaltSync(saltRounds);
  const hashedPassword = bcrypt.hashSync(password, salt);
  await User.create({
    username,
    password: hashedPassword,
  });
  res.redirect("/");
});

router.get("/login", (req, res) => {
  res.render("auth/login");
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.render("auth/login", {
      errorMessage: "Fill username and password",
    });
    return;
  }

  const user = await User.findOne({ username });
  if (!user) {
    res.render("auth/login", {
      errorMessage: "Invalid login",
    });
    return;
  }

  //Check for password
  if (bcrypt.compareSync(password, user.password)) {
    //Passwords match

    //Initializing the session with the current user
    req.session.currentUser = user;

    res.redirect("/");
  } else {
    //Passwords don't match
    res.render("auth/login", {
      errorMessage: "Invalid login",
    });
  }
});

router.post("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});


module.exports = router;
