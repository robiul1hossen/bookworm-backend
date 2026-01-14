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
    const addToReadCollection = db.collection("addToRead");
    const currentlyReadingCollection = db.collection("currently-reading");
    const readCollection = db.collection("read");

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

    app.get("/genres", verifyToken, async (req, res) => {
      const result = await genresCollection.find().toArray();
      res.send(result);
    });
    app.patch("/genres/:id", verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;
      const newGenre = req.body;
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
      const { page = 1, limit = 10, search = "", genre, sort } = req.query;
      const skip = (Number(page) - 1) * Number(limit);
      let query = {};
      if (search) {
        query.title = { $regex: search, $options: "i" };
      }
      if (genre) {
        query.genres = genre;
      }
      let sortQuery = {};
      if (sort === "rating_asc") {
        sortQuery.rating = 1;
      }
      if (sort === "rating_desc") {
        sortQuery.rating = -1;
      }
      const result = await booksCollection
        .find(query)
        .sort(sortQuery)
        .skip(Number(skip))
        .limit(Number(limit))
        .toArray();
      const total = await booksCollection.countDocuments(query);

      res.send({
        result,
        total,
        page: Number(page),
        limit: Number(limit),
        totalPage: Math.ceil(total / limit),
      });
    });
    app.get("/books/reviews", verifyToken, async (req, res) => {
      const result = await booksCollection
        .aggregate([
          { $match: { reviews: { $exists: true, $not: { $size: 0 } } } },
          { $unwind: "$reviews" },
          { $match: { "reviews.status": "pending" } },

          {
            $project: {
              _id: 0,
              bookId: "$_id",
              rating: "$reviews.rating",
              comment: "$reviews.comment",
              name: "$reviews.name",
              email: "$reviews.email",
              date: "$reviews.date",
              status: "$reviews.status",
            },
          },
        ])
        .toArray();
      res.send(result);
    });
    app.patch("/reviews/approve", verifyToken, async (req, res) => {
      const { bookId, userEmail, reviewDate } = req.body;

      const query = {
        _id: new ObjectId(bookId),
        reviews: {
          $elemMatch: {
            email: userEmail,
            date: reviewDate,
          },
        },
      };

      const updateDoc = {
        $set: { "reviews.$.status": "approved" },
      };

      try {
        const result = await booksCollection.updateOne(query, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Update fail hoyeche" });
      }
    });
    app.get("/books/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const query = { _id: new ObjectId(id) };
      const result = await booksCollection.findOne(query);
      res.send(result);
    });
    app.patch("/books/review/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const newReview = req.body;
      const query = { _id: new ObjectId(id) };
      const updatedDoc = {
        $push: {
          reviews: newReview,
        },
      };
      const result = await booksCollection.updateOne(query, updatedDoc);
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

    // shelf related api
    app.post("/shelf/want-to-read", verifyToken, async (req, res) => {
      const bookData = req.body;
      const email = bookData.email;
      const bookId = bookData.bookId;
      const isExisting = await addToReadCollection.findOne({ email, bookId });
      if (isExisting) {
        return res.send("This book is already in your shelf");
      }
      const result = await addToReadCollection.insertOne(bookData);
      res.send(result);
    });
    app.post(`/shelf/currently-reading`, verifyToken, async (req, res) => {
      const bookData = req.body;
      const email = bookData.email;
      const bookId = bookData.bookId;
      const isExisting = await currentlyReadingCollection.findOne({
        email,
        bookId,
      });
      if (isExisting) {
        return res.send("This book is already in your shelf");
      }
      const result = await currentlyReadingCollection.insertOne(bookData);
      res.send(result);
    });
    app.post(`/shelf/read`, verifyToken, async (req, res) => {
      const bookData = req.body;
      const email = bookData.email;
      const bookId = bookData.bookId;
      const isExisting = await readCollection.findOne({
        email,
        bookId,
      });
      if (isExisting) {
        return res.send("This book is already in your shelf");
      }
      const result = await readCollection.insertOne(bookData);
      res.send(result);
    });
    app.get("/want-to-read", verifyToken, async (req, res) => {
      const { email } = req.query;
      const result = await addToReadCollection
        .aggregate([
          { $match: { email: email } },

          {
            $addFields: {
              bookId: { $toObjectId: "$bookId" },
            },
          },

          {
            $lookup: {
              from: "books",
              localField: "bookId",
              foreignField: "_id",
              as: "bookData",
            },
          },

          { $unwind: "$bookData" },
        ])
        .toArray();
      res.send(result);
    });
    app.get("/currently-reading", verifyToken, async (req, res) => {
      const { email } = req.query;
      const result = await currentlyReadingCollection
        .aggregate([
          { $match: { email: email } },
          {
            $addFields: {
              bookId: { $toObjectId: "$bookId" },
            },
          },
          {
            $lookup: {
              from: "books",
              localField: "bookId",
              foreignField: "_id",
              as: "bookData",
            },
          },

          { $unwind: "$bookData" },
        ])
        .toArray();
      res.send(result);
    });
    app.get("/read", verifyToken, async (req, res) => {
      const { email } = req.query;
      const result = await readCollection
        .aggregate([
          { $match: { email: email } },
          {
            $addFields: {
              bookId: { $toObjectId: "$bookId" },
            },
          },
          {
            $lookup: {
              from: "books",
              localField: "bookId",
              foreignField: "_id",
              as: "bookData",
            },
          },

          { $unwind: "$bookData" },
        ])
        .toArray();
      res.send(result);
    });

    // stats related apis
    app.get("/genre-stats", verifyToken, verifyAdmin, async (req, res) => {
      const stats = await booksCollection
        .aggregate([
          {
            $unwind: "$genres",
          },

          {
            $group: {
              _id: "$genres",
              count: { $sum: 1 },
            },
          },

          {
            $project: {
              name: "$_id",
              count: 1,
              _id: 0,
            },
          },

          { $sort: { count: -1 } },
        ])
        .toArray();
      res.send(stats);
    });
    app.get(
      "/user-register-stats",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const trend = await usersCollection
          .aggregate([
            {
              $group: {
                _id: {
                  $dateToString: { format: "%d-%m-%Y", date: "$createdAt" },
                },
                count: { $sum: 1 },
              },
            },
            { $sort: { _id: 1 } },
            {
              $project: {
                date: "$_id",
                users: "$count",
                _id: 0,
              },
            },
          ])
          .toArray();

        res.send(trend);
      }
    );
    app.get("/shelf-book-count", verifyToken, async (req, res) => {
      const { email } = req.query;
      const [currentlyReading, addToRead, read] = await Promise.all([
        db.collection("currently-reading").countDocuments({ email }),
        db.collection("addToRead").countDocuments({ email }),
        db.collection("read").countDocuments({ email }),
      ]);
      const result = [
        {
          name: "Currently Reading",
          count: currentlyReading,
        },
        { name: "Want To Read", count: addToRead },
        { name: "Read", count: read },
      ];
      res.send(result);
    });

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!"
    // );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`BookWorm is listening on port ${port}`);
});
