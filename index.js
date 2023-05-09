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
  admin: Joi.boolean().optional(),
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

const expireTime = 1 * 0 * 0 * 0; //expires after 1 hour  (hours * minutes * seconds * millis)

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

const isAdmin = async (req, res, next) => {
  if (!req.session.isAuth) {
    return res.redirect("/");
  }

  try {
    const user = await UserModel.findOne({ email: req.session.userEmail });
    if (!user || !user.admin) {
      return res.redirect("/dashboard");
    }

    next();
  } catch (error) {
    console.error("Error checking user admin status:", error);
    res.redirect("/dashboard");
  }
};

app.get("/landing", redirectToDashboardIfAuth, (req, res) => {
  res.render("landing");
});

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
    return res
      .status(400)
      .render("login", { error: "Invalid email or password" });
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res
      .status(400)
      .render("login", { error: "Invalid email or password" });
  }

  req.session.isAuth = true;
  req.session.userEmail = email; // Store the user's email in the session
  res.redirect("/dashboard");
});

app.get("/register", redirectToDashboardIfAuth, (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const admin = req.body.admin === "on" ? true : false;

  const validationResult = schema.validate({
    username,
    email,
    password,
    admin,
  });
  if (validationResult.error) {
    console.log(validationResult.error);
    return res.redirect("/register");
  }

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
      admin: admin,
    });

    await user.save();
    res.redirect("/login");
  } catch (error) {
    console.error("Error hashing password:", error);
    res.redirect("/register");
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

app.get("/admin", isAdmin, async (req, res) => {
  try {
    const users = await UserModel.find({});
    res.render("admin", { users });
  } catch (error) {
    console.error("Error fetching users:", error);
    res
      .status(500)
      .render("error", { error: "An error occurred while fetching users" });
  }
});

app.get("/promote/:id", isAdmin, async (req, res) => {
  try {
    await UserModel.updateOne({ _id: req.params.id }, { admin: true });
    res.redirect("/admin");
  } catch (error) {
    console.error("Error promoting user:", error);
    res
      .status(500)
      .render("error", { error: "An error occurred while promoting user" });
  }
});

app.get("/demote/:id", isAdmin, async (req, res) => {
  try {
    await UserModel.updateOne({ _id: req.params.id }, { admin: false });
    res.redirect("/admin");
  } catch (error) {
    console.error("Error demoting user:", error);
    res
      .status(500)
      .render("error", { error: "An error occurred while demoting user" });
  }
});


app.listen(port, () => {
  console.log("Node application listening on port" + port);
});

app.use((req, res) => {
  res.status(404).render("404");
});
