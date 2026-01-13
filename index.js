const express = require("express");
const cors = require("cors");
const { ObjectId } = require("mongodb");
require("dotenv").config();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion } = require("mongodb");

const app = express();
const port = process.env.PORT || 3000;
app.use(express.json());
app.use(cors());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.zf7rutj.mongodb.net/?appName=Cluster0`;

const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );
};

// verify jwt
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send({ message: "Invalid token" });
  }
};

const verifyAdmin = (req, res, next) => {
  // console.log(req.role);
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Forbidden" });
  }
  next();
};

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const db = client.db("bookworm");
    const usersCollection = db.collection("users");
    const genresCollection = db.collection("genres");
    const booksCollection = db.collection("books");

    // user related apis
    app.post("/user/signup", async (req, res) => {
      const user = req.body;
      if (!user) {
        return res.status(400).send({ message: "User data is required" });
      }

      const email = user.email;
      const isExisting = await usersCollection.findOne({ email });
      if (isExisting) {
        return res.status(400).send({ message: "User already exist" });
      }
      const saltRounds = 10;
      const plainPassword = user.password;
      const hashedAdminPassword = await bcrypt.hash(plainPassword, saltRounds);
      const userToDB = {
        name: user.name,
        email: user.email,
        password: hashedAdminPassword,
        photoURL: user.photoURL,
        role: "user",
        createdAt: new Date(),
      };
      const result = await usersCollection.insertOne(userToDB);
      const newUser = {
        id: result.insertedId,
        name: user.name,
        email: user.email,
        role: "user",
      };

      const token = generateToken(newUser);
      res.status(201).send({
        message: "Signup successful",
        token,
        user: newUser,
      });
    });
    app.post("/user/login", async (req, res) => {
      const { email, password } = req.body;
      if (!email || !password) {
        return res.status(401).send({ message: "User data is required" });
      }
      const user = await usersCollection.findOne({ email });
      if (!user) {
        return res.status(401).send({ message: "Invalid user credentials" });
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).send({ message: "Invalid user credentials" });
      }

      const token = generateToken(user);

      res.status(200).send({
        message: "Login successful",
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    });
    app.get("/user/me", verifyToken, async (req, res) => {
      const user = await usersCollection.findOne(
        { _id: new ObjectId(req.user.id) },
        { projection: { password: 0 } }
      );

      res.send({ user });
    });
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const result = await usersCollection
        .find({}, { projection: { password: 0 } })
        .toArray();
      res.send(result);
    });
    app.patch("/user/role/:id", verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;
      const query = { _id: new ObjectId(id) };
      const role = req.body;
      console.log(role);
      const updatedDoc = { $set: { role: role?.role } };
      const result = await usersCollection.updateOne(query, updatedDoc);
      res.send(result);
    });
    // genres related apis
    app.post("/genres", verifyToken, verifyAdmin, async (req, res) => {
      const genres = req.body;
      const result = await genresCollection.insertOne(genres);
      res.send(result);
    });

    app.get("/genres", verifyToken, verifyAdmin, async (req, res) => {
      const result = await genresCollection.find().toArray();
      res.send(result);
    });
    app.patch("/genres/:id", verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;
      const newGenre = req.body;
      console.log(newGenre);
      const query = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: { ...newGenre },
      };
      const result = await genresCollection.updateOne(query, updatedDoc);
      res.send(result);
    });
    app.delete("/genres/:id", verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;
      const query = { _id: new ObjectId(id) };
      const result = await genresCollection.deleteOne(query);
      res.send(result);
    });

    // book related apis
    app.post("/books", verifyToken, verifyAdmin, async (req, res) => {
      const book = req.body;
      const result = await booksCollection.insertOne(book);
      res.send(result);
    });
    app.get("/books", verifyToken, async (req, res) => {
      const result = await booksCollection.find().toArray();
      res.send(result);
    });
    app.get("/books/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const query = { _id: new ObjectId(id) };
      const result = await booksCollection.findOne(query);
      res.send(result);
    });
    app.patch("/books/:id", verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;
      const newBookData = req.body;
      const query = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          ...newBookData,
        },
      };
      const result = await booksCollection.updateOne(query, updatedDoc);
      res.send(result);
    });
    app.delete("/books/:id", verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;
      const query = { _id: new ObjectId(id) };
      const result = await booksCollection.deleteOne(query);
      res.send(result);
    });
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`BookWorm is listening on port ${port}`);
});
