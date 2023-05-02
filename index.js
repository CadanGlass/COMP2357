const express = require("express");
const dotenv = require("dotenv");
dotenv.config();
const session = require("express-session");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const MongoDBSession = require("connect-mongodb-session")(session);
const app = express();
const port = process.env.PORT || 3000;
const node_session_secret = process.env.NODE_SESSION_SECRET;
const mongoURI = process.env.MONGO_URI;
const path = require("path");
const saltRounds = 12;
const UserModel = require("./models/user");
const publicPath = path.join(__dirname, "images");
const Joi = require("joi");

const schema = Joi.object({
  username: Joi.string().alphanum().max(20).required(),
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});





app.use(express.static(publicPath));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));

mongoose
  .connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then((res) => {
    console.log("MongoDB Connected");
  });

const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

const mongoStore = new MongoDBSession({
  uri: mongoURI,
  collection: "sessions",
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    rolling: true,
  })
);



const isAuth = (req, res, next) => {
  if (req.session.isAuth) {
    next();
  } else {
    res.redirect("/");
  }
};

// Middleware to redirect to dashboard if authenticated
const redirectToDashboardIfAuth = (req, res, next) => {
  if (req.session.isAuth) {
    res.redirect("/dashboard");
  } else {
    next();
  }
};

app.get("/", redirectToDashboardIfAuth, (req, res) => {
  res.render("landing");
});

app.get("/login", redirectToDashboardIfAuth, (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
 const validationResult = loginSchema.validate(req.body);
 if (validationResult.error) {
   console.log(validationResult.error);
   return res.redirect("/login");
 }
  const { email, password } = req.body;

  const user = await UserModel.findOne({ email });

  if (!user) {
    return res.redirect("/login");
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.redirect("/login");
  }

  req.session.isAuth = true;
  req.session.userEmail = email; // Store the user's email in the session
  res.redirect("/dashboard");
});

app.get("/register", redirectToDashboardIfAuth, (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {

  const validationResult = schema.validate(req.body);
  if (validationResult.error) {
    console.log(validationResult.error);

    return res.redirect("/register");
  }
  const { username, email, password } = req.body;

  console.log("Username:", username);
  console.log("Email:", email);
  console.log("Password:", password);

  let user = await UserModel.findOne({ email });

  if (user) {
    return res.redirect("/register");
  }

  try {
    const hashedPsw = await bcrypt.hash(password, saltRounds);

    user = new UserModel({
      username,
      email,
      password: hashedPsw,
    });

    await user.save();
    res.redirect("/login");
  } catch (error) {
    console.error("Error hashing password:", error);
    res.redirect("/register");
  }
});

app.get("/dashboard", isAuth, async (req, res) => {
  try {
    const user = await UserModel.findOne({ email: req.session.userEmail });

    if (user) {
      const randomNumber = Math.floor(Math.random() * 3) + 1; // Generate a random number between 1 and 3
      const randomImage = `image${randomNumber}.jpg`;
      res.render("dashboard", { username: user.username, image: randomImage });
    } else {
      res.redirect("/login");
    }
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.redirect("/login");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.redirect("/dashboard");
    }
    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

app.listen(port, () => {
  console.log("Node application listening on port" + port);
});

app.use((req, res) => {
  res.status(404).render("404");
});
