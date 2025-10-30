// backend/server.js
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
dotenv.config();
const app = express();

// --- Safety checks ---
if (!process.env.MONGO_URI) {
  console.error("❌ MONGO_URI not set in environment");
  process.exit(1);
}
if (!process.env.JWT_SECRET) {
  console.error("❌ JWT_SECRET not set in environment");
  process.exit(1);
}
if (!process.env.ADMIN_SECRET) {
  console.error("❌ ADMIN_SECRET not set in environment");
  process.exit(1);
}

// --- Encryption Helpers ---
const ENC_KEY = process.env.ENC_KEY || "12345678901234567890123456789012"; // must be 32 bytes
const IV_LENGTH = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(ENC_KEY), iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function decrypt(text) {
  try {
    if (!text) return null;
    if (!text.includes(":")) return text;
    const parts = text.split(":");
    if (parts.length !== 2) return text;
    const iv = Buffer.from(parts[0], "hex");
    const encryptedText = Buffer.from(parts[1], "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(ENC_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString("utf8");
  } catch (err) {
    console.error("❌ Token decryption failed:", err.message);
    return null;
  }
}

// --- Proper CORS Setup ---
const allowedOrigins = [
  "http://localhost:5173",
  "https://code-sharing-frontend-pi.vercel.app", // ✅ Added correct production URL
];

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps or curl)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      } else {
        return callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"],
    credentials: true,
  })
);


const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per 15 mins
  message: "Too many login attempts. Try again later."
});
app.use("/api/auth/login", loginLimiter);
app.disable('x-powered-by');

// --- Middleware ---
app.use(express.json());
app.use(helmet());

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 200, // 200 requests per IP per 15 min
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);


// --- MongoDB Connection ---
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// --- Example route to confirm CORS ---
app.get("/cors-test", (req, res) => {
  res.json({ message: "✅ CORS is working fine!" });
});



// ---------- Schemas ----------
const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, trim: true },
    email: { type: String, unique: true, required: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    githubToken: { type: String, default: "" },
    githubUsername: { type: String, default: "" }, // optional


  },
  { timestamps: true }
);

const snippetSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    language: { type: String, default: "javascript", lowercase: true, trim: true },
    code: { type: String, default: "" },
    author: { type: String, required: true },
    isPublic: { type: Boolean, default: true, index: true },
    tags: [{ type: String, trim: true, lowercase: true }],
     likes: [
      {
        userId: { type: String, required: true },
        date: { type: Date, default: Date.now },
      },
    ],

    comments: [
      {
        user: { type: String, required: true },
        text: { type: String, required: true },
        createdAt: { type: Date, default: Date.now },
      },
    ],

    
    views: { type: Number, default: 0 },
    viewedBy: [{ type: mongoose.Schema.Types.Mixed }], 
  },
  { timestamps: true }
);

const collectionSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    snippets: [{ type: mongoose.Schema.Types.ObjectId, ref: "Snippet" }],
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Snippet = mongoose.model("Snippet", snippetSchema);
const Collection = mongoose.model("Collection", collectionSchema);

// ---------- DB Connect ----------
mongoose
  .connect(process.env.MONGO_URI, {
    autoIndex: true,
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => {
    console.error("Mongo connect error:", err);
    process.exit(1);
  });

// ---------- Auth middleware ----------
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Missing authorization header" });

  const [scheme, token] = auth.split(" ");
  if (scheme !== "Bearer" || !token)
    return res.status(401).json({ error: "Invalid authorization header" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid / expired token" });
  }
};

// ---------- Admin middleware ----------
const verifyAdmin = (req, res, next) => {
  const key = req.headers["x-admin-key"];
  if (!key || key !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: "Unauthorized admin access" });
  }
  next();
};

const verifyTokenOptional = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return next(); // guest

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    next(); // invalid token → treat as guest
  }
};


// =============================================================
// =============== AUTH ROUTES ================================
// =============================================================

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    if (!username || !email || !password)
      return res.status(400).json({ error: "Missing fields" });

    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) return res.status(400).json({ error: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ username, email: email.toLowerCase(), password: hashedPassword });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.status(201).json({ token, user: { username: user.username, email: user.email } });
  } catch (err) {
    console.error("signup error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Missing fields" });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.json({ token, user: { username: user.username, email: user.email } });
  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/auth/me", async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: "Missing token" });

    const [scheme, token] = auth.split(" ");
    if (scheme !== "Bearer" || !token)
      return res.status(401).json({ error: "Invalid token format" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("username email createdAt");
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ user });
  } catch (err) {
    console.error("auth/me error:", err);
    res.status(401).json({ error: "Invalid or expired token" });
  }
});

// // Save GitHub token (from profile page)
// app.post("/api/user/github-token", verifyToken, async (req, res) => {
//   try {
//     const { token } = req.body;
//     if (!token) return res.status(400).json({ error: "Missing token" });

//       const crypto = require("crypto");
//       const ENC_KEY = process.env.ENC_KEY || "12345678901234567890123456789012"; // 32 bytes key
//       const IV = Buffer.alloc(16, 0);

//       function encrypt(text) {
//         const cipher = crypto.createCipheriv("aes-256-cbc", ENC_KEY, IV);
//         let encrypted = cipher.update(text, "utf8", "hex");
//         encrypted += cipher.final("hex");
//         return encrypted;
//       }
//       function decrypt(text) {
//         const decipher = crypto.createDecipheriv("aes-256-cbc", ENC_KEY, IV);
//         let decrypted = decipher.update(text, "hex", "utf8");
//         decrypted += decipher.final("utf8");
//         return decrypted;
//       }


//     const user = await User.findById(req.userId);
//     user.githubToken = token;
//     await user.save();


//     res.json({ message: "GitHub token saved successfully!" });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // Remove GitHub token
// app.delete("/api/user/github-token", verifyToken, async (req, res) => {
//   try {
//     await User.findByIdAndUpdate(req.userId, { githubToken: "" });
//     res.json({ message: "GitHub token removed" });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// =============================================================
// =============== USER GITHUB INTEGRATION ======================
// =============================================================


app.put("/api/user/update", async (req, res) => {
  try {
    const userId = req.user.id; // decoded from JWT
    const { username, bio } = req.body;

    const updated = await User.findByIdAndUpdate(
      userId,
      { username, bio },
      { new: true }
    ).select("-password");

    res.json({ user: updated });
  } catch (err) {
    res.status(500).json({ error: "Failed to update profile" });
  }
});


// ✅ Save + Verify GitHub Token
// =============================================================
// =============== USER GITHUB INTEGRATION ======================
// =============================================================

// ✅ Save GitHub Token (frontend sends token)
app.post("/api/user/github-token", verifyToken, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: "Missing GitHub token" });

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const encryptedToken = encrypt(token);

    // Verify token directly with GitHub
    const ghRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `token ${token}`,
        "User-Agent": "CodeSharingApp",
      },
    });

    if (!ghRes.ok) return res.status(401).json({ error: "Invalid GitHub token" });

    const ghData = await ghRes.json();

    // Save to user profile
    user.githubToken = encryptedToken;
    user.githubUsername = ghData.login;
    user.githubEmail = ghData.email;
    user.githubAvatar = ghData.avatar_url;
    await user.save();

    res.json({
      success: true,
      githubUsername: ghData.login,
      githubEmail: ghData.email,
      githubAvatar: ghData.avatar_url,
    });
  } catch (err) {
    console.error("GitHub token save error:", err);
    res.status(500).json({ error: "Server error saving GitHub token" });
  }
});


// ✅ Get current user’s GitHub info
app.get("/api/user/github-token", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select(
      "githubToken githubUsername githubEmail githubAvatar username email"
    );

    if (!user) return res.status(404).json({ error: "User not found" });

    if (!user.githubToken) {
      return res.json({
        connected: false,
        githubUsername: null,
        githubEmail: null,
        githubAvatar: null,
        username: user.username,
        email: user.email,
      });
    }

    const decryptedToken = decrypt(user.githubToken);

    const ghRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `token ${decryptedToken}`,
        "User-Agent": "CodeSharingApp",
      },
    });

    if (ghRes.status === 401) {
      user.githubToken = "";
      user.githubUsername = null;
      user.githubEmail = null;
      user.githubAvatar = null;
      await user.save();

      return res.json({
        connected: false,
        expired: true,
        message: "GitHub token invalid or expired — please reconnect.",
      });
    }

    const ghData = await ghRes.json();

    res.json({
      connected: true,
      githubUsername: user.githubUsername || ghData.login,
      githubEmail: user.githubEmail || ghData.email,
      githubAvatar: user.githubAvatar || ghData.avatar_url,
      username: user.username,
      email: user.email,
    });
  } catch (err) {
    console.error("Fetch GitHub token error:", err);
    res.status(500).json({ error: "Server error verifying GitHub token" });
  }
});




// ✅ Remove GitHub token (disconnect)
app.delete("/api/user/github-token", verifyToken, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.userId,
      { githubToken: "", githubUsername: "" },
      { new: true }
    );

    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ message: "GitHub disconnected successfully" });
  } catch (err) {
    console.error("Disconnect GitHub error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/users/:username", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username })
      .select("username githubUsername githubAvatar createdAt")
      .lean();
    if (!user) return res.status(404).json({ error: "User not found" });

    const snippets = await Snippet.find({ author: user.username, isPublic: true }).lean();
    res.json({ user, snippets });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// =============================================================
// =============== ADMIN GITHUB MANAGEMENT =====================
// =============================================================

// // Save GitHub token (from profile page)
// app.post("/api/user/github-token", verifyToken, async (req, res) => {
//   try {
//     const { token } = req.body;
//     if (!token) return res.status(400).json({ error: "Missing token" });

//     const crypto = require("crypto");
//     const ENC_KEY = process.env.ENC_KEY || "12345678901234567890123456789012"; // 32-byte key
//     const IV = Buffer.alloc(16, 0);

//     function encrypt(text) {
//       const cipher = crypto.createCipheriv("aes-256-cbc", ENC_KEY, IV);
//       let encrypted = cipher.update(text, "utf8", "hex");
//       encrypted += cipher.final("hex");
//       return encrypted;
//     }

//     const user = await User.findById(req.userId);
//     if (!user) return res.status(404).json({ error: "User not found" });

//     user.githubToken = encrypt(token);
//     await user.save();

//     res.json({ message: "GitHub token saved securely!" });
//   } catch (err) {
//     console.error("GitHub token save error:", err);
//     res.status(500).json({ error: err.message });
//   }
// });


app.get("/api/admin/github-users", verifyAdmin, async (req, res) => {
  try {
    const users = await User.find({
      githubToken: { $exists: true, $ne: "" },
    })
      .select("username email githubUsername githubToken createdAt")
      .lean();

    // Mask token for privacy
    const safeUsers = users.map((u) => ({
      ...u,
      githubToken: u.githubToken
        ? "••••••" + u.githubToken.slice(-6)
        : "",
    }));

    res.json(safeUsers);
  } catch (err) {
    console.error("Error fetching GitHub users:", err);
    res.status(500).json({ error: "Failed to fetch GitHub users" });
  }
});



// ✅ Revoke GitHub token (reset connection)
// ✅ Revoke GitHub token (reset connection and clear GitHub username)
app.post("/api/admin/github-users/revoke/:userId", verifyAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    // Find user
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // If user still has a token, try to fetch their GitHub username before revoking
    let githubUsername = user.githubUsername;
    if (user.githubToken) {
      try {
        const ghRes = await fetch("https://api.github.com/user", {
          headers: { Authorization: `token ${user.githubToken}` },
        });

        if (ghRes.ok) {
          const ghData = await ghRes.json();
          githubUsername = ghData.login || githubUsername;
        }
      } catch (ghErr) {
        console.warn("⚠️ GitHub API check failed before revoke:", ghErr.message);
      }
    }

    // Clear both token and username
    user.githubToken = "";
    user.githubUsername = "";
    await user.save();

    res.json({
      message: "✅ GitHub connection revoked successfully",
      revokedUser: {
        id: user._id,
        username: user.username,
        githubUsername: githubUsername || null,
      },
    });
  } catch (err) {
    console.error("Error revoking GitHub token:", err);
    res.status(500).json({ error: "Failed to revoke GitHub token" });
  }
});


// =============================================================
// =============== ADMIN AUTH (NEW!) ===========================
// =============================================================

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;
  const adminUser = process.env.ADMIN_USER;
  const adminPass = process.env.ADMIN_PASS;

  if (username === adminUser && password === adminPass) {
    return res.json({ message: "Admin authenticated", adminKey: process.env.ADMIN_SECRET });
  } else {
    return res.status(403).json({ error: "Invalid admin credentials" });
  }
});

// =============================================================
// =============== ADMIN PROTECTED ROUTES ======================
// =============================================================

// All admin routes below this line require x-admin-key header
app.use("/api/admin", verifyAdmin);

// Admin stats
app.get("/api/admin/stats", async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalSnippets = await Snippet.countDocuments();

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const activeToday = await Snippet.distinct("author", {
      createdAt: { $gte: today },
    }).then((u) => u.length);

    res.json({ totalUsers, totalSnippets, activeToday });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ Get all users (for AdminUsersPage)
app.get("/api/admin/users", async (req, res) => {
  try {
    const users = await User.find()
      .select("_id username email createdAt")
      .sort({ createdAt: -1 })
      .lean();
    res.json(users);
  } catch (err) {
    console.error("admin users fetch error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ✅ Delete user by ID
app.delete("/api/admin/users/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Delete the user
    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) return res.status(404).json({ error: "User not found" });

    // Optional: delete all snippets authored by that user
    await Snippet.deleteMany({ author: deletedUser.username });

    // Optional: delete all collections owned by that user
    await Collection.deleteMany({ owner: id });

    res.json({ message: "User and related data deleted successfully" });
  } catch (err) {
    console.error("admin delete user error:", err);
    res.status(500).json({ error: err.message });
  }
});
// Admin snippets
app.get("/api/admin/snippets", async (req, res) => {
  const snippets = await Snippet.find().lean();
  res.json(snippets);
});

app.delete("/api/admin/snippets/:id", async (req, res) => {
  const { id } = req.params;
  await Snippet.findByIdAndDelete(id);
  await Collection.updateMany({ snippets: id }, { $pull: { snippets: id } });
  res.json({ message: "Snippet deleted" });
});

// User Growth (last 30 days)
app.get("/api/admin/user-growth", verifyAdmin, async (req, res) => {
  try {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 29); // last 30 days
    startDate.setHours(0, 0, 0, 0);

    const users = await User.find({ createdAt: { $gte: startDate } }).sort({ createdAt: 1 });

    const growthData = [];
    for (let i = 0; i < 30; i++) {
      const day = new Date();
      day.setDate(day.getDate() - (29 - i));
      day.setHours(0, 0, 0, 0);

      const count = users.filter(u => u.createdAt >= day && u.createdAt < new Date(day.getTime() + 86400000)).length;
      growthData.push({ date: day.toISOString().split("T")[0], count });
    }

    res.json(growthData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Snippet Activity (last 30 days)
app.get("/api/admin/snippet-activity", verifyAdmin, async (req, res) => {
  try {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 29); // last 30 days
    startDate.setHours(0, 0, 0, 0);

    const snippets = await Snippet.find({ createdAt: { $gte: startDate } }).sort({ createdAt: 1 });

    const activityData = [];
    for (let i = 0; i < 30; i++) {
      const day = new Date();
      day.setDate(day.getDate() - (29 - i));
      day.setHours(0, 0, 0, 0);

      const count = snippets.filter(s => s.createdAt >= day && s.createdAt < new Date(day.getTime() + 86400000)).length;
      activityData.push({ date: day.toISOString().split("T")[0], snippets: count });
    }

    res.json(activityData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


// ================== SNIPPETS ==================

// Create snippet
app.post("/api/snippets", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(401).json({ error: "User not found" });

    const { title, description, language, code, isPublic, tags } = req.body || {};
    if (!title) return res.status(400).json({ error: "Title is required" });

    const snippet = new Snippet({
      title: title.trim(),
      description: description || "",
      language: (language || "javascript").toLowerCase().trim(),
      code: code || "",
      author: user.username,
      isPublic: !!isPublic,
      tags: tags?.map((t) => t.toLowerCase().trim()) || [],
    });

    await snippet.save();
    return res.status(201).json(snippet);
  } catch (err) {
    console.error("create snippet error:", err);
    return res.status(400).json({ error: err.message });
  }
});

// Public snippets
// Public snippets with pagination
app.get("/api/snippets/public", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const [snippets, total] = await Promise.all([
      Snippet.find({ isPublic: true })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Snippet.countDocuments({ isPublic: true }),
    ]);

    return res.json({
      snippets,
      page,
      totalPages: Math.ceil(total / limit),
      total,
    });
  } catch (err) {
    console.error("get public snippets error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// Search snippets with pagination (same shape as /public)
// ✅ Improved Search Route
app.get("/api/snippets/search", async (req, res) => {
  try {
    const { q } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    if (!q || !q.trim()) {
      return res.json([]);
    }

    const regex = new RegExp(q.trim(), "i");

    const filter = {
      isPublic: true,
      $or: [
        { title: regex },
        { description: regex },
        { language: regex },
        { tags: regex },
        { author: regex },
      ],
    };

    const snippets = await Snippet.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    res.json(snippets);
  } catch (err) {
    console.error("search error:", err);
    res.status(500).json({ error: "Server error while searching" });
  }
});




// ✅ Weekly Trending Snippets (based on likes in the last 7 days)
app.get("/api/snippets/trending", async (req, res) => {
  try {
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    // Fetch snippets that are public and created or liked within 7 days
    const snippets = await Snippet.aggregate([
      { $match: { isPublic: true } },
      {
        $addFields: {
          recentLikes: {
            $filter: {
              input: "$likes",
              as: "like",
              cond: { $gte: ["$$like.date", oneWeekAgo] }, // filter likes from last 7 days
            },
          },
        },
      },
      {
        $addFields: {
          recentLikesCount: { $size: "$recentLikes" },
        },
      },
      { $sort: { recentLikesCount: -1, createdAt: -1 } },
      { $limit: 6 },
    ]);

    res.json(snippets);
  } catch (err) {
    console.error("🔥 Trending fetch error:", err);
    res.status(500).json({ error: err.message });
  }
});


// ---------------------- EXPLORE SNIPPETS (Improved: Likes + Views Ranking) ----------------------
app.get("/api/snippets/explore", async (req, res) => {
  try {
    console.log("📥 [Explore] API called");

    // Limit & select only required fields for performance
    const allSnippets = await Snippet.find({ isPublic: true })
      .select("title description language likes views createdAt author tags")
      .limit(500)
      .lean();

    if (!allSnippets || allSnippets.length === 0) {
      console.log("⚠️ No public snippets found!");
      return res.json({ trending: [], recent: [], byLanguage: {} });
    }

    console.log("✅ Total public snippets:", allSnippets.length);

    // --- Trending Snippets (weighted by likes + views) ---
    const trending = allSnippets
      .map((s) => ({
        ...s,
        popularityScore: (s.likes?.length || 0) * 2 + (s.views || 0) * 0.5, // weighted
      }))
      .sort((a, b) => b.popularityScore - a.popularityScore)
      .slice(0, 8); // top 8 trending

    // --- Recent Snippets (by creation date) ---
    const recent = allSnippets
      .filter((s) => s?.createdAt)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 12);

    // --- Group by Language (case-insensitive) ---
    const byLanguage = {};
    for (const snippet of allSnippets) {
      try {
        const lang = snippet?.language
          ? String(snippet.language).toLowerCase()
          : "other";
        if (!byLanguage[lang]) byLanguage[lang] = [];
        if (byLanguage[lang].length < 10) byLanguage[lang].push(snippet);
      } catch (innerErr) {
        console.warn("⚠️ Failed to group snippet:", snippet._id, innerErr.message);
      }
    }

    console.log(
      `🔥 Trending: ${trending.length}, 🆕 Recent: ${recent.length}, 🌐 Languages: ${Object.keys(byLanguage).length}`
    );

    res.json({ trending, recent, byLanguage });
  } catch (err) {
    console.error("❌ [Explore] route error:", err.message);
    res.status(500).json({ error: "Internal server error in /api/snippets/explore" });
  }
});



// Current user's snippets
app.get("/api/snippets/mine", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(401).json({ error: "User not found" });

    const snippets = await Snippet.find({ author: user.username }).sort({ createdAt: -1 }).lean();
    return res.json(snippets);
  } catch (err) {
    console.error("get mine error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// Get single snippet
app.get("/api/snippets/:id", async (req, res) => {
  try {
    const snippet = await Snippet.findById(req.params.id).lean();
    if (!snippet) return res.status(404).json({ error: "Snippet not found" });
    return res.json(snippet);
  } catch (err) {
    console.error("get snippet by id error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// Delete snippet
app.delete("/api/snippets/:id", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(401).json({ error: "User not found" });

    const snippet = await Snippet.findById(req.params.id);
    if (!snippet) return res.status(404).json({ error: "Snippet not found" });

    if (snippet.author !== user.username) {
      return res.status(403).json({ error: "Not authorized" });
    }

    await Snippet.findByIdAndDelete(req.params.id);
    return res.json({ message: "Snippet deleted" });
  } catch (err) {
    console.error("delete snippet error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// Update snippet
app.put("/api/snippets/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, language, code, isPublic, tags } = req.body || {};
    if (!title) return res.status(400).json({ error: "Title is required" });

    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(401).json({ error: "User not found" });

    const snippet = await Snippet.findById(id);
    if (!snippet) return res.status(404).json({ error: "Snippet not found" });
   
    snippet.title = title.trim();
    snippet.description = description || "";
    snippet.language = (language || "javascript").toLowerCase().trim();
    snippet.code = code || "";
    snippet.isPublic = typeof isPublic === "boolean" ? isPublic : snippet.isPublic;
    snippet.tags = tags?.map((t) => t.toLowerCase().trim()) || snippet.tags;

const updated = await Snippet.findByIdAndUpdate(
  id,
  {
    $set: {
      title: title.trim(),
      description: description || "",
      language: (language || "javascript").toLowerCase().trim(),
      code: code || "",
      isPublic: !!isPublic,
      tags: tags?.map((t) => t.toLowerCase().trim()) || [],
    },
  },
  { new: true } // ✅ returns updated document
);

return res.json(updated);

  } catch (err) {
    console.error("update snippet error:", err);
    return res.status(500).json({ error: err.message });
  }
});


// ================== SNIPPET EXTRAS ==================

// Like / Unlike
app.post("/api/snippets/:id/like", verifyToken, async (req, res) => {
  try {
    const snippet = await Snippet.findById(req.params.id);
    if (!snippet) return res.status(404).json({ error: "Snippet not found" });

    const userId = req.userId;

    // ✅ Check if this user already liked the snippet
    const existingLikeIndex = snippet.likes.findIndex(
      (like) => like.userId === userId
    );

    if (existingLikeIndex !== -1) {
      // ✅ Unlike (remove like entry)
      snippet.likes.splice(existingLikeIndex, 1);
    } else {
      // ✅ Add a new like with timestamp
      snippet.likes.push({ userId, date: new Date() });
    }

    await snippet.save();

    // ✅ Populate only like count & return updated snippet
    return res.json({
      _id: snippet._id,
      likesCount: snippet.likes.length,
      likes: snippet.likes,
      message:
        existingLikeIndex !== -1 ? "Unliked successfully" : "Liked successfully",
    });
  } catch (err) {
    console.error("like error:", err);
    return res.status(500).json({ error: err.message });
  }
});


// Add comment
// Add comment
app.post("/api/snippets/:id/comments", verifyToken, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: "Comment text is required" });

    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(401).json({ error: "User not found" });

    const snippet = await Snippet.findById(req.params.id);
    if (!snippet) return res.status(404).json({ error: "Snippet not found" });

    // ✅ Push comment with username
    snippet.comments.push({
      user: user.username,
      text,
    });

    await snippet.save();
    return res.json(snippet);
  } catch (err) {
    console.error("comment error:", err);
    return res.status(500).json({ error: err.message });
  }
});


// ✅ Delete a comment safely
app.delete("/api/snippets/:id/comments/:commentId", verifyToken, async (req, res) => {
  try {
    const snippet = await Snippet.findById(req.params.id);
    if (!snippet) return res.status(404).json({ error: "Snippet not found" });

    const user = await User.findById(req.userId);
    if (!user) return res.status(401).json({ error: "User not found" });

    // ✅ Find the comment manually
    const commentIndex = snippet.comments.findIndex(
      (c) => c._id.toString() === req.params.commentId
    );
    if (commentIndex === -1)
      return res.status(404).json({ error: "Comment not found" });

    const comment = snippet.comments[commentIndex];

    // ✅ Check permission (only comment author or snippet author)
    if (comment.user !== user.username && snippet.author !== user.username) {
      return res
        .status(403)
        .json({ error: "Not authorized to delete this comment" });
    }

    // ✅ Remove comment by index
    snippet.comments.splice(commentIndex, 1);
    await snippet.save();

    return res.json({ message: "Comment deleted", snippet });
  } catch (err) {
    console.error("delete comment error:", err);
    return res.status(500).json({ error: err.message });
  }
});




app.post("/api/snippets/:id/view", async (req, res) => {
  try {
    const snippet = await Snippet.findById(req.params.id);
    if (!snippet) return res.status(404).json({ error: "Snippet not found" });

    const userIdOrIp = req.userId || req.ip; // logged-in user or guest IP

    // Make sure viewedBy is an array
    if (!snippet.viewedBy) snippet.viewedBy = [];

    // Only increment if not already viewed
    if (!snippet.viewedBy.includes(userIdOrIp)) {
      snippet.views += 1;
      snippet.viewedBy.push(userIdOrIp);
      await snippet.save();
    }

    res.json({ message: "View recorded", views: snippet.views });
  } catch (err) {
    console.error("Error updating views:", err);
    res.status(500).json({ error: "Server error while recording view" });
  }
});




app.post("/api/snippets/:id/sync-github", verifyToken, async (req, res) => {
  try {
    const snippet = await Snippet.findById(req.params.id);
    if (!snippet) return res.status(404).json({ error: "Snippet not found" });

    const user = await User.findById(req.userId);
    if (!user || !user.githubToken) {
      return res.status(400).json({ error: "GitHub not connected" });
    }

    // 🔐 Decrypt token safely
    const decryptedToken = decrypt(user.githubToken);
    if (!decryptedToken) {
      return res.status(400).json({
        error: "Stored GitHub token invalid or corrupted. Please reconnect GitHub.",
      });
    }

    // ✅ Sync snippet to user's GitHub as a Gist
    const gistResponse = await fetch("https://api.github.com/gists", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${decryptedToken}`,
      },
      body: JSON.stringify({
        description: snippet.description || "Shared via CodeX",
        public: snippet.isPublic,
        files: {
          [`${snippet.title || "snippet"}.${snippet.language || "txt"}`]: {
            content: snippet.code || "",
          },
        },
      }),
    });

    const gistData = await gistResponse.json();
    if (!gistResponse.ok) {
      return res.status(400).json({ error: gistData.message || "GitHub sync error" });
    }

    snippet.gistUrl = gistData.html_url;
    await snippet.save();

    res.json({
      message: "✅ Snippet synced successfully!",
      gistUrl: gistData.html_url,
    });
  } catch (err) {
    console.error("GitHub sync error:", err);
    res.status(500).json({ error: "Server error syncing to GitHub" });
  }
});



// ================== PUBLIC SNIPPET SEARCH ==================
app.get("/api/snippets/search", async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.trim() === "") return res.json([]);

    const regex = new RegExp(q, "i"); // case-insensitive search

    const snippets = await Snippet.find({
      isPublic: true,
      $or: [
        { title: regex },
        { author: regex },
        { language: regex },
        { description: regex },
        { tags: regex },
        { "author.username": regex },
      ],
    })
      .sort({ createdAt: -1 })
      .lean();

    res.json(snippets);
  } catch (err) {
    console.error("search error:", err);
    res.status(500).json({ error: err.message });
  }
});


// ✅ Get snippets by tag (public only)
app.get("/api/snippets/tag/:tag", async (req, res) => {
  try {
    const { tag } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const regex = new RegExp(tag, "i"); // case-insensitive match
    const [snippets, total] = await Promise.all([
      Snippet.find({ isPublic: true, tags: regex })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Snippet.countDocuments({ isPublic: true, tags: regex }),
    ]);

    return res.json({
      snippets,
      page,
      totalPages: Math.ceil(total / limit),
      total,
    });
  } catch (err) {
    console.error("get snippets by tag error:", err);
    return res.status(500).json({ error: err.message });
  }
});




// ================== COLLECTIONS ==================

// Create new collection
app.post("/api/collections", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(401).json({ error: "User not found" });

    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: "Collection name required" });

    const collection = new Collection({
      name: name.trim(),
      description: description || "",
      owner: req.userId,
    });

    await collection.save();
    res.status(201).json(collection);
  } catch (err) {
    console.error("create collection error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Get user’s collections
app.get("/api/collections", verifyToken, async (req, res) => {
  try {
    const collections = await Collection.find({ owner: req.userId })
      .sort({ createdAt: -1 })
      .lean();
    res.json(collections);
  } catch (err) {
    console.error("fetch collections error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Get single collection
app.get("/api/collections/:id", verifyToken, async (req, res) => {
  try {
    const collection = await Collection.findOne({
      _id: req.params.id,
      owner: req.userId,
    })
      .populate("snippets")
      .lean();

    if (!collection) return res.status(404).json({ error: "Collection not found" });
    res.json(collection);
  } catch (err) {
    console.error("get collection error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Update collection
app.put("/api/collections/:id", verifyToken, async (req, res) => {
  try {
    const { name, description } = req.body;
    const collection = await Collection.findOne({
      _id: req.params.id,
      owner: req.userId,
    });

    if (!collection) return res.status(404).json({ error: "Collection not found" });
    if (name) collection.name = name.trim();
    if (description) collection.description = description;

    await collection.save();
    res.json(collection);
  } catch (err) {
    console.error("update collection error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Add snippet to collection
app.put("/api/collections/:id/add-snippet", verifyToken, async (req, res) => {
  try {
    const { snippetId } = req.body;
    if (!snippetId)
      return res.status(400).json({ error: "Snippet ID required" });

    const collection = await Collection.findOne({
      _id: req.params.id,
      owner: req.userId,
    });

    if (!collection) return res.status(404).json({ error: "Collection not found" });

    if (!collection.snippets.includes(snippetId)) {
      collection.snippets.push(snippetId);
      await collection.save();
    }

    res.json(collection);
  } catch (err) {
    console.error("add-snippet error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Delete collection
app.delete("/api/collections/:id", verifyToken, async (req, res) => {
  try {
    const result = await Collection.findOneAndDelete({
      _id: req.params.id,
      owner: req.userId,
    });

    if (!result) return res.status(404).json({ error: "Collection not found" });
    res.json({ message: "Collection deleted" });
  } catch (err) {
    console.error("delete collection error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
