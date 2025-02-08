import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";

dotenv.config();
const { Pool } = pkg;

const app = express();
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
pool.connect()
  .then(() => console.log("✅ Connected to PostgreSQL database"))
  .catch((err) => console.error("❌ Database connection error:", err.message));
app.use(cors());
app.use(express.json());
console.log("Connecting to database:", process.env.DB_NAME);

// Create a Contact
app.post("/contacts", async (req, res) => {
  try {
    const { name, address, phone } = req.body;
    const newContact = await pool.query(
      "INSERT INTO contacts (name, address, phone) VALUES ($1, $2, $3) RETURNING *",
      [name, address, phone]
    );
    res.json(newContact.rows[0]);
  } catch (err) {
    console.error(err.message);
  }
});

// Get All Contacts
app.get("/contacts", async (req, res) => {
  try {
    const contacts = await pool.query("SELECT * FROM contacts");
    res.json(contacts.rows);
  } catch (err) {
    console.error(err.message);
  }
});

// Get a Single Contact
app.get("/contacts/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const contact = await pool.query("SELECT * FROM contacts WHERE id = $1", [id]);
    res.json(contact.rows[0]);
  } catch (err) {
    console.error(err.message);
  }
});

// Update a Contact
app.put("/contacts/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { name, address, phone } = req.body;
    await pool.query(
      "UPDATE contacts SET name = $1, address = $2, phone = $3 WHERE id = $4",
      [name, address, phone, id]
    );
    res.json({ message: "Contact updated!" });
  } catch (err) {
    console.error(err.message);
  }
});

// Delete a Contact
app.delete("/contacts/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query("DELETE FROM contacts WHERE id = $1", [id]);
    res.json({ message: "Contact deleted!" });
  } catch (err) {
    console.error(err.message);
  }
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});