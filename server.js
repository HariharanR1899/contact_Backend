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

// import express from "express";
// import cors from "cors";
// import dotenv from "dotenv";
// import pkg from "pg";
// import bcrypt from "bcryptjs";
// import jwt from "jsonwebtoken";

// dotenv.config();
// const { Pool } = pkg;
// const app = express();
// const pool = new Pool({
//   connectionString: process.env.DATABASE_URL,
//   ssl: { rejectUnauthorized: false },
// });

// const JWT_SECRET = "your_secret_key"; // Change this in production

// app.use(cors());
// app.use(express.json());

// // ✅ Register User
// app.post("/register", async (req, res) => {
//   const { email, password } = req.body;
//   const hashedPassword = await bcrypt.hash(password, 10);

//   try {
//     const result = await pool.query(
//       "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
//       [email, hashedPassword]
//     );
//     res.json(result.rows[0]);
//   } catch (err) {
//     res.status(400).json({ error: "User already exists" });
//   }
// });

// // ✅ Login User
// app.post("/login", async (req, res) => {
//   const { email, password } = req.body;

//   try {
//     const user = await pool.query("SELECT * FROM users WHERE email = $1", [
//       email,
//     ]);
//     if (!user.rows.length)
//       return res.status(400).json({ error: "Invalid email or password" });

//     const validPassword = await bcrypt.compare(password, user.rows[0].password);
//     if (!validPassword)
//       return res.status(400).json({ error: "Invalid email or password" });

//     const token = jwt.sign({ userId: user.rows[0].id }, JWT_SECRET, {
//       expiresIn: "1h",
//     });
//     const userid = user.rows[0].id;;
//     res.json({ token, userid });
//   } catch (err) {
//     console.error(err.message);
//     res.status(500).send("Server error");
//   }
// });

// // ✅ Middleware: Authenticate User
// const authenticate = (req, res, next) => {
//   const token = req.headers["authorization"];
//   if (!token) return res.status(401).json({ error: "Unauthorized" });

//   try {
//     const decoded = jwt.verify(token, JWT_SECRET);
//     req.userId = decoded.userId;
//     next();
//   } catch (err) {
//     res.status(401).json({ error: "Invalid token" });
//   }
// };

// // ✅ Fetch Contacts (Per User)
// app.get("/contacts", authenticate, async (req, res) => {
//   try {
//     const contacts = await pool.query(
//       "SELECT * FROM contacts WHERE user_id = $1",
//       [req.userId]
//     );
//     res.json(contacts.rows);
//   } catch (err) {
//     console.error(err.message);
//     res.status(500).send("Server error");
//   }
// });

// // ✅ Create Contact (Per User)
// app.post("/contacts", authenticate, async (req, res) => {
//   const { name, address, phone } = req.body;
//   try {
//     const newContact = await pool.query(
//       "INSERT INTO contacts (name, address, phone, user_id) VALUES ($1, $2, $3, $4) RETURNING *",
//       [name, address, phone, req.userId]
//     );
//     res.json(newContact.rows[0]);
//   } catch (err) {
//     console.error(err.message);
//     res.status(500).send("Server error");
//   }
// });

// // ✅ Update Contact (Only Own Contacts)
// app.put("/contacts/:id", authenticate, async (req, res) => {
//   const { id } = req.params;
//   const { name, address, phone } = req.body;

//   try {
//     await pool.query(
//       "UPDATE contacts SET name = $1, address = $2, phone = $3 WHERE id = $4 AND user_id = $5",
//       [name, address, phone, id, req.userId]
//     );
//     res.json({ message: "Contact updated!" });
//   } catch (err) {
//     console.error(err.message);
//     res.status(500).send("Server error");
//   }
// });

// // ✅ Delete Contact (Only Own Contacts)
// app.delete("/contacts/:id", authenticate, async (req, res) => {
//   const { id } = req.params;

//   try {
//     await pool.query("DELETE FROM contacts WHERE id = $1 AND user_id = $2", [
//       id,
//       req.userId,
//     ]);
//     res.json({ message: "Contact deleted!" });
//   } catch (err) {
//     console.error(err.message);
//     res.status(500).send("Server error");
//   }
// });

// const PORT = process.env.PORT || 5001;
// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import nodemailer from "nodemailer";
import crypto from "crypto";

dotenv.config();
const { Pool } = pkg;
const app = express();

// ✅ PostgreSQL Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key";
const OTP_EXPIRY_TIME = 10 * 60 * 1000; // 10 minutes

// ✅ Middleware
app.use(cors());
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your_session_secret",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ✅ Configure Email Transporter (Nodemailer)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ✅ Google OAuth Strategy
passport.use(
  "google-login",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.GOOGLE_CALLBACK_URL}/auth/google/login/callback`, // FIXED ✅
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const { email } = profile._json;
        let user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

        if (!user.rows.length) {
          console.log("🚀 No account found for:", email);
          return done(null, false);
        }

        const token = jwt.sign({ userId: user.rows[0].id }, JWT_SECRET, { expiresIn: "1h" });

        return done(null, { token, userid: user.rows[0].id });
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.use(
  "google-signup",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.GOOGLE_CALLBACK_URL}/auth/google/signup/callback`, // FIXED ✅
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const { email } = profile._json;
        let user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

        if (user.rows.length > 0) {
          console.log("🚀 Account already exists for:", email);
          return done(null, false);
        }

        // ✅ Create a new user in DB
        user = await pool.query(
          "INSERT INTO users (email, google_id) VALUES ($1, $2) RETURNING id, email",
          [email, profile.id]
        );

        console.log("✅ New Google account created for:", email);

        return done(null, { userid: user.rows[0].id, isNewUser: true }); // ✅ Mark as new user
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

app.get(
  "/auth/google/login",
  passport.authenticate("google-login", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/login/callback",
  passport.authenticate("google-login", { failureRedirect: "/login?error=NoAccount" }),
  (req, res) => {
    if (!req.user) {
      return res.redirect(`${process.env.FRONTEND_URL}/login?error=NoAccount`);
    }

    const { token, userid } = req.user;
    res.redirect(`${process.env.FRONTEND_URL}/auth-redirect?token=${encodeURIComponent(token)}&userid=${encodeURIComponent(userid)}`);
  }
);
app.get(
  "/auth/google/signup",
  passport.authenticate("google-signup", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/signup/callback",
  passport.authenticate("google-signup", { failureRedirect: "/signup?error=AlreadyExists" }),
  (req, res) => {
    if (!req.user) {
      return res.redirect(`${process.env.FRONTEND_URL}/signup?error=AlreadyExists`);
    }

    res.redirect(`${process.env.FRONTEND_URL}/login?success=SignedUp`);
  }
);                                                                                                                

app.get("/auth/google/signup/failure", (req, res) => {
  res.redirect(`${process.env.FRONTEND_URL}/signup?error=AlreadyExists`);
});

app.get("/auth/google/login/failure", (req, res) => {
  res.redirect(`${process.env.FRONTEND_URL}/login?error=NoAccount`);
});

// ✅ Serialize & Deserialize User
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ✅ Google OAuth Routes
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// app.get(
//   "/auth/google/callback",
//   passport.authenticate("google", { failureRedirect: "/" }),
//   (req, res) => {
//     const { token, userid } = req.user;
//     res.redirect(`${process.env.FRONTEND_URL}/contacts?token=${token}&userid=${userid}`); // ✅ Redirecting to "/contacts"
//   }
// );`` 

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login?error=NoAccount" }),
  async (req, res) => {
    try {
      const { token, userid, isNewUser } = req.user;

      if (!token || !userid) {
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=missing_token`);
      }

      // ✅ Handle Google Signup vs Login
      if (isNewUser) {
        return res.redirect(`${process.env.FRONTEND_URL}/signup?signupSuccess=true`);
      }

      return res.redirect(`${process.env.FRONTEND_URL}/auth-redirect?token=${token}&userid=${userid}`);
    } catch (error) {
      console.error("Google OAuth Callback Error:", error);
      res.redirect("/login?error=server_error");
    }
  }
);

app.get("/auth/google/failure", (req, res) => {
  res.redirect(`${process.env.FRONTEND_URL}/?error=NoAccount`);
});

// ✅ Send OTP for Signup
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  const otp = crypto.randomInt(100000, 999999).toString();

  try {
    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "User already exists" });
    }

    await pool.query(
      "INSERT INTO otps (email, otp, expires_at) VALUES ($1, $2, NOW() + INTERVAL '10 minutes') ON CONFLICT (email) DO UPDATE SET otp = EXCLUDED.otp, expires_at = EXCLUDED.expires_at",
      [email, otp]
    );

    await transporter.sendMail({
      from: `"Contacts App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your OTP for Signup",
      text: `Your OTP is: ${otp}. It expires in 10 minutes.`,
    });

    res.json({ message: "OTP sent to email." });
  } catch (error) {
    console.error("Error sending OTP:", error);
    res.status(500).json({ error: "Error sending OTP" });
  }
});

// ✅ Verify OTP and Create User
// ✅ Send OTP for Signup (Only if User is Not Present)
// ✅ Verify OTP and Create User (Signup)
app.post("/verify-otp", async (req, res) => {
  const { email, otp, password } = req.body;

  try {
    // ✅ Check if OTP is valid
    const result = await pool.query(
      "SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()",
      [email, otp]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    // ✅ Check if user already exists (to prevent duplicate accounts)
    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "User already registered. Please log in." });
    }

    // ✅ Hash password and create new user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
      [email, hashedPassword]
    );

    // ✅ Delete OTP after successful verification
    await pool.query("DELETE FROM otps WHERE email = $1", [email]);

    res.json({ message: "Account created successfully", user: newUser.rows[0] });
  } catch (error) {
    console.error("Error verifying OTP:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Login User (Email & Password)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (user.rows.length === 0) {
      return res.status(400).json({ error: "Account not found. Please sign up." });
    }

    if (!user.rows[0].password) {
      return res.status(403).json({ error: "This account uses Google Sign-In. Please log in with Google." }); // ✅ Google login message
    }

    const isValid = await bcrypt.compare(password, user.rows[0].password);
    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const token = jwt.sign({ userId: user.rows[0].id }, JWT_SECRET, { expiresIn: "1h" });

    res.json({ token, userid: user.rows[0].id });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ✅ Middleware: Authenticate User
const authenticate = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ✅ CRUD for Contacts
app.get("/contacts", authenticate, async (req, res) => {
  try {
    const contacts = await pool.query("SELECT * FROM contacts WHERE user_id = $1", [req.userId]);
    res.json(contacts.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

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

// ✅ Update Contact (PUT)
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

// ✅ Delete Contact
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

// ✅ Send OTP for Forgot Password
app.post("/send-forgot-password-otp", async (req, res) => {
  const { email } = req.body;
  const otp = crypto.randomInt(100000, 999999).toString();

  try {
    // ✅ Check if user exists
    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!existingUser.rows.length) {
      return res.status(400).json({ error: "Email not registered" });
    }

    // ✅ Store OTP in database
    await pool.query(
      "INSERT INTO otps (email, otp, expires_at) VALUES ($1, $2, NOW() + INTERVAL '10 minutes') ON CONFLICT (email) DO UPDATE SET otp = EXCLUDED.otp, expires_at = EXCLUDED.expires_at",
      [email, otp]
    );

    // ✅ Send OTP via email
    await transporter.sendMail({
      from: `"Contacts App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your OTP for Password Reset",
      text: `Your OTP is: ${otp}. It expires in 10 minutes.`,
    });

    res.json({ message: "OTP sent to email." });
  } catch (error) {
    console.error("Error sending forgot password OTP:", error);
    res.status(500).json({ error: "Error sending OTP" });
  }
});

// ✅ Verify OTP & Reset Password
app.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    // ✅ Validate OTP
    const result = await pool.query(
      "SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()",
      [email, otp]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    // ✅ Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // ✅ Update user's password
    await pool.query("UPDATE users SET password = $1 WHERE email = $2", [hashedPassword, email]);

    // ✅ Delete OTP after password reset
    await pool.query("DELETE FROM otps WHERE email = $1", [email]);

    res.json({ message: "Password reset successful. You can now log in with your new password." });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ error: "Server error" });
  }
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

// ✅ Logout (Clears Session)
app.get("/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy();
    res.redirect("/");
  });
});

