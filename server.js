// import express from "express";
// import cors from "cors";
// import dotenv from "dotenv";
// import pkg from "pg";

// dotenv.config();
// const { Pool } = pkg;

// const app = express();
// const pool = new Pool({
//     connectionString: process.env.DATABASE_URL, // ✅ Use single URL
//     ssl: {
//       rejectUnauthorized: false, // ✅ Required for Render PostgreSQL
//     },
//   });
// pool.connect()
//   .then(() => console.log("✅ Connected to PostgreSQL database"))
//   .catch((err) => console.error("❌ Database connection error:", err.message));
// app.use(cors());
// app.use(express.json());
// console.log("Connecting to database:", process.env.DB_NAME);

// // Create a Contact
// app.post("/contacts", async (req, res) => {
//   try {
//     const { name, address, phone } = req.body;
//     const newContact = await pool.query(
//       "INSERT INTO contacts (name, address, phone) VALUES ($1, $2, $3) RETURNING *",
//       [name, address, phone]
//     );
//     res.json(newContact.rows[0]);
//   } catch (err) {
//     console.error(err.message);
//   }
// });

// app.get("/", (req, res) => {
//     res.send("✅ Contacts API is running!");
//   });

// // Get All Contacts
// app.get("/contacts", async (req, res) => {
//   try {
//     const contacts = await pool.query("SELECT * FROM contacts");
//     res.json(contacts.rows);
//   } catch (err) {
//     console.error(err.message);
//   }
// });

// // Get a Single Contact
// app.get("/contacts/:id", async (req, res) => {
//   try {
//     const { id } = req.params;
//     const contact = await pool.query("SELECT * FROM contacts WHERE id = $1", [id]);
//     res.json(contact.rows[0]);
//   } catch (err) {
//     console.error(err.message);
//   }
// });

// // Update a Contact
// app.put("/contacts/:id", async (req, res) => {
//   try {
//     const { id } = req.params;
//     const { name, address, phone } = req.body;
//     await pool.query(
//       "UPDATE contacts SET name = $1, address = $2, phone = $3 WHERE id = $4",
//       [name, address, phone, id]
//     );
//     res.json({ message: "Contact updated!" });
//   } catch (err) {
//     console.error(err.message);
//   }
// });

// // Delete a Contact
// app.delete("/contacts/:id", async (req, res) => {
//   try {
//     const { id } = req.params;
//     await pool.query("DELETE FROM contacts WHERE id = $1", [id]);
//     res.json({ message: "Contact deleted!" });
//   } catch (err) {
//     console.error(err.message);
//   }
// });

// const PORT = process.env.PORT || 5001;
// app.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
// });

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();
const { Pool } = pkg;
const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = "your_secret_key"; // Change this in production

app.use(cors());
app.use(express.json());

// ✅ Register User
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
      [email, hashedPassword]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(400).json({ error: "User already exists" });
  }
});

// ✅ Login User
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!user.rows.length) return res.status(400).json({ error: "Invalid email or password" });

    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) return res.status(400).json({ error: "Invalid email or password" });

    const token = jwt.sign({ userId: user.rows[0].id }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// ✅ Middleware: Authenticate User
const authenticate = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ✅ Fetch Contacts (Per User)
app.get("/contacts", authenticate, async (req, res) => {
  try {
    const contacts = await pool.query("SELECT * FROM contacts WHERE user_id = $1", [req.userId]);
    res.json(contacts.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// ✅ Create Contact (Per User)
app.post("/contacts", authenticate, async (req, res) => {
  const { name, address, phone } = req.body;
  try {
    const newContact = await pool.query(
      "INSERT INTO contacts (name, address, phone, user_id) VALUES ($1, $2, $3, $4) RETURNING *",
      [name, address, phone, req.userId]
    );
    res.json(newContact.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// ✅ Update Contact (Only Own Contacts)
app.put("/contacts/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  const { name, address, phone } = req.body;

  try {
    await pool.query(
      "UPDATE contacts SET name = $1, address = $2, phone = $3 WHERE id = $4 AND user_id = $5",
      [name, address, phone, id, req.userId]
    );
    res.json({ message: "Contact updated!" });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// ✅ Delete Contact (Only Own Contacts)
app.delete("/contacts/:id", authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query("DELETE FROM contacts WHERE id = $1 AND user_id = $2", [id, req.userId]);
    res.json({ message: "Contact deleted!" });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));