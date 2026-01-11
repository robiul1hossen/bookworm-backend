const express = require("express");
const cors = require("cors");
require("dotenv").config();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion } = require("mongodb");

const app = express();
const port = process.env.PORT || 3000;
app.use(express.json());
app.use(cors());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.zf7rutj.mongodb.net/?appName=Cluster0`;

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
      const plainPassword = user.password.toString();
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
      res.status(201).send({
        message: "User added successfully",
        insertedId: result.insertedId,
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
      const isPasswordValid = await bcrypt.compare(
        password.toString(),
        user.password
      );
      if (!isPasswordValid) {
        return res.status(401).send({ message: "Invalid user credentials" });
      }

      const token = jwt.sign(
        { id: user._id.toString(), email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );

      res.status(201).send({
        message: "User login successfully",
        token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
      });
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
