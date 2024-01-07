// All imports start from here---
const express = require("express");
const dotenv = require("dotenv");
dotenv.config();
const cors = require("cors");
const mongoose = require("mongoose");
const User = require("./models/User.js");
const Post = require("./models/Posts.js");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Multer = require("multer");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const compression = require("compression");
const cloudinary = require("cloudinary");
const { frontendUrl } = require("./helper.js");
const apicache = require("apicache");
let cache = apicache.middleware;
// All imports end here---
const app = express();
const salt = bcrypt.genSaltSync(10);
const corsOptions = {
  origin: "https://blogo-1tkw.onrender.com",
  credentials: true,
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS",
  optionsSuccessStatus: 200,
  allowedHeaders: "Content-Type,Authorization",
};
// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));
// parse application/json
app.use(bodyParser.json());
app.use(cors(corsOptions));
app.use(helmet());
app.use(compression());
app.use(express.json());
app.use(cookieParser());

// handling uncaught exceptions--
process.on("uncaughtException", (err) => {
  console.log(`error: ${err.message}`);
  console.log(`Uncaught exception: ${err.stack}`);
  process.exit(1);
});

// some secret variables--
const db = process.env.DB;
const jwtSecret = process.env.JWT_SECRET;

// cloudinary image upload functionality starts here--
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

async function handleUpload(file) {
  const res = await cloudinary.uploader.upload(file, {
    resource_type: "auto",
  });
  return res;
}
const storage = new Multer.memoryStorage();
const upload = Multer({
  storage,
});
// cloudinary image upload functionality ends here--

// DB connection ---
mongoose
  .connect(db, {
    useNewUrlParser: true,
  })
  .then(() => console.log("database connected!"))
  .catch((err) => console.log(err.stack));

// cookies options--
const cookieOpions = {
  httpOnly: true,
  expiresIn: process.env.JWT_COOKIE_EXPIRATION,
  secure: true,
  sameSite: "None",
};
// api routes start from here---
// user register route--
app.post("/register", upload.single("file"), async (req, res) => {
  try {
    let cldRes;
    if (req.file) {
      const b64 = Buffer.from(req.file.buffer).toString("base64");
      let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
      cldRes = await handleUpload(dataURI);
    }

    const { username, password, email, desc, link } = req.body;

    if (username === "" || password === "" || email === "") {
      return res.status(404).json({ message: "please fill all the input" });
    }

    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
      email,
      desc,
      link,
      cover: req.file ? cldRes.secure_url : undefined,
    });

    res.status(201).json({
      data: userDoc,
      message: "successfully registered.",
    });
  } catch (err) {
    if (err.code === 11000) {
      const duplicateKeys = Object.keys(err.keyValue).join(",");
      err.message = `Duplicate field entered: ${duplicateKeys}`;
    }
    res.status(404).json({
      message: err.message,
    });
  }
});

// user login route---
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const userDoc = await User.findOne({ email });

    if (email === "" || password === "") {
      return res
        .status(404)
        .json({ message: "Please enter proper email and password." });
    }

    const passOk = await bcrypt.compare(password, userDoc.password);
    if (!passOk) {
      return res.status(404).json({ message: "Wrong password!" });
    }
    if (passOk) {
      jwt.sign(
        { username: userDoc.username, id: userDoc.id, cover: userDoc.cover },
        jwtSecret,
        { expiresIn: "1d" },
        (err, token) => {
          if (err) throw err;
          res.cookie("token", token, { cookieOpions }).json({
            id: userDoc._id,
            username: userDoc.username,
            message: "Successfully logged in.",
          });
        }
      );
    }
  } catch (err) {
    res.status(404).json({
      message: "Something went wrong!",
    });
  }
});

// home routes--
app.get("/profile", async (req, res) => {
  try {
    const { token } = req.cookies;
    jwt.verify(token, jwtSecret, {}, (err, info) => {
      if (err) throw err;
      res.json(info);
    });
  } catch (err) {
    res.status(404).json({
      status: "Failed",
      message: "Something went wrong!",
    });
  }
});

// userDetails route---
app.get("/userDetails/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const userDoc = await User.findById(id);
    res.status(200).json({
      success: true,
      username: userDoc.username,
      desc: userDoc.desc,
      link: userDoc.link,
      cover: userDoc.cover,
    });
  } catch (error) {
    res.status(404).json({
      status: "Failed",
      message: "Something went wrong!",
    });
  }
});
// user-profile-data routes --
app.get("/userProfile/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const userDoc = await User.findById(id);
    const postDoc = await Post.find()
      .populate("author", {
        username: 1,
        _id: 1,
        cover: 1,
      })
      .sort({ createdAt: -1 });
    const filteredPost = postDoc.filter((post) => {
      return id === post.author._id.valueOf();
    });
    res.status(200).json({
      success: true,
      username: userDoc.username,
      desc: userDoc.desc,
      link: userDoc.link,
      cover: userDoc.cover,
      filteredPost,
    });
  } catch (error) {
    res.status(404).json({
      status: "Failed",
      message: "Something went wrong!",
    });
  }
});
// user-details-edit page--
app.patch("/userDetailsEdit/:id", upload.single("file"), async (req, res) => {
  try {
    const { id } = req.params;
    let cldRes;
    if (req.file) {
      const b64 = Buffer.from(req.file.buffer).toString("base64");
      let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
      cldRes = await handleUpload(dataURI);
    }

    const { token } = req.cookies;
    jwt.verify(token, jwtSecret, {}, async (err, info) => {
      if (err) throw err;
      const { username, desc, link } = req.body;
      const userDoc = await User.findById(id);

      await User.findByIdAndUpdate(id, {
        username,
        desc,
        link,
        cover: req.file ? cldRes.secure_url : userDoc.cover,
      });
      res.status(201).json({ userDoc, message: "successfully updated" });
    });
  } catch (error) {
    res.status(404).json({
      status: "Failed",
      message: "Something went wrong!",
    });
  }
});

// user logout routes---
app.post("/logout", (req, res) => {
  try {
    const { token } = req.cookies;

    res
      .cookie("token", null, {
        expires: new Date(Date.now()),
        httpOnly: true,
      })
      .json({
        token: token,
        message: "Successfully logged out!",
      });
  } catch (err) {
    res.status(404).json({
      status: "Failed",
      message: "Somthing went wrong!",
    });
  }
});

// create post routes--
app.post("/createPost", upload.single("file"), async (req, res) => {
  let cldRes;
  if (req.file) {
    const b64 = Buffer.from(req.file.buffer).toString("base64");
    let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
    cldRes = await handleUpload(dataURI);
  }

  try {
    const { token } = req.cookies;
    jwt.verify(token, jwtSecret, {}, async (err, info) => {
      if (err) throw err;
      const { title, summary, content } = req.body;
      if (title === "" || summary === "" || content === "") {
        return res
          .status(404)
          .json({ message: "Please enter all the required fields!" });
      }
      const postDoc = await Post.create({
        title,
        summary,
        content,
        cover: req.file ? cldRes.secure_url : undefined,
        author: info.id,
      });
      res.status(201).json({
        postDoc,
        message: "Successfully post created.",
      });
    });
  } catch (error) {
    res.status(404).json({
      status: "Failed",
      message: "something went wrong!",
    });
  }
});

// get post data --
app.get("/post", async (req, res) => {
  try {
    const postDoc = await Post.find()
      .populate("author", {
        username: 1,
        _id: 1,
        cover: 1,
      })
      .sort({ createdAt: -1 });
    res.status(200).json({
      success: true,
      data: postDoc,
    });
  } catch (error) {
    res.status(404).json({
      status: "Failed",
      message: "something went wrong!",
    });
  }
});

// get single post data --
app.get("/singlePost/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const postDoc = await Post.findById(id).populate("author", {
      username: 1,
      _id: 1,
    });

    res.status(200).json({ status: "success", data: postDoc });
  } catch (error) {
    res.status(404).json({
      status: "Failed",
      message: "something went wrong!",
    });
  }
});

// get post data for editing--
app.get("/editPost/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const postDoc = await Post.findById(id).populate("author", {
      username: 1,
      _id: 1,
    });

    res.status(200).json({ status: "success", data: postDoc });
  } catch (error) {
    res.status(404).json({
      status: "Failed",
      message: "something went wrong!",
    });
  }
});

// edit single post --
app.patch("/editPost/:id", upload.single("file"), async (req, res) => {
  try {
    const { id } = req.params;
    let cldRes;
    if (req.file) {
      const b64 = Buffer.from(req.file.buffer).toString("base64");
      let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
      cldRes = await handleUpload(dataURI);
    }

    const { token } = req.cookies;
    jwt.verify(token, jwtSecret, {}, async (err, info) => {
      if (err) throw err;
      const { title, summary, content } = req.body;
      const postDoc = await Post.findById(id);
      const isAuthor =
        JSON.stringify(postDoc.author) === JSON.stringify(info.id);
      if (!isAuthor) return;
      if (!isAuthor) {
        return res.status(400).json("You are not the author!");
      }

      await Post.findByIdAndUpdate(id, {
        title,
        summary,
        content,
        cover: req.file ? cldRes.secure_url : postDoc.cover,
      });
      res.json({ postDoc, message: "Successfully post updated" });
    });
  } catch (err) {
    res.status(404).json({
      status: "Failed",
      message: "Something went wrong!",
    });
  }
});

// search routes --
app.get("/search", cache("5 minutes"), async (req, res) => {
  try {
    const { search } = req.query;

    const posts = await Post.find({
      title: { $regex: search, $options: "i" },
    })
      .populate("author", {
        username: 1,
        cover: 1,
        _id: 1,
      })
      .sort({ createdAt: -1 });

    res.status(200).json({
      message: "Fetched posts",
      data: posts,
    });
  } catch (error) {
    res.status(404).json({
      status: "Failed",
      message: "Something went wrong!",
    });
  }
});
// test routes--
app.get("/", (req, res) => {
  res.send("hello world!");
});

// server creation---
app.listen(process.env.PORT || 4000, () => {
  console.log(`Listening on port 4000`);
});
// unhandled promise rejection--
process.on("unhandledRejection", (err) => {
  console.log(`Error: ${err}`);
  console.log(`Shuting down the server due to unhandled promise rejection!`);

  server.close(() => {
    process.exit(1);
  });
});
