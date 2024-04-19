require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

const dbConnectionString = process.env.DB_CONNECTION_STRING;

mongoose
  .connect(dbConnectionString, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

const User = mongoose.model(
  "User",
  new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
  })
);

app.use(express.json());
app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: "lax",
    },
  })
);
app.use(
  cors({
    origin: "http://localhost:4200",
    credentials: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email }).exec();
        if (!user) {
          return done(null, false, { message: "Incorrect email." });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return done(null, false, { message: "Incorrect password." });
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id).exec(); // Use async/await and exec()
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: user._id,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Registration error", err);
    res
      .status(500)
      .json({ message: "Registration failed", error: err.message });
  }
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      console.error("Login error", err);
      return res
        .status(500)
        .json({ message: "Login error", error: err.message });
    }
    if (!user) {
      return res.status(401).json(info); // `info` contains the message set by the Passport strategy
    }
    req.logIn(user, (err) => {
      if (err) {
        console.error("Session login error", err);
        return res
          .status(500)
          .json({ message: "Login session error", error: err.message });
      }
      return res.json({
        message: "Logged in successfully",
        user: {
          id: user._id,
          email: user.email,
        },
      });
    });
  })(req, res, next);
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      console.error("Logout error", err);
      return res
        .status(500)
        .json({ message: "Logout failed", error: err.message });
    }
    res.json({ message: "Logged out successfully" });
  });
});

app.get("/auth/status", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      isAuthenticated: true,
      user: {
        email: req.user.email,
        id: req.user._id,
      },
    });
  } else {
    res.json({ isAuthenticated: false });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
