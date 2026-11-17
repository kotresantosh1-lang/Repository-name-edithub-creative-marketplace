
// server.js — Edit Hub App Backend
// Node.js + Express + MongoDB (Mongoose)
// Install: npm init -y && npm i express mongoose cors dotenv bcryptjs jsonwebtoken multer

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

// ---------- Middleware ----------
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ---------- File upload ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /image\/(jpeg|png|jpg|webp)|video\/(mp4|webm)|application\/pdf/.test(file.mimetype);
    cb(ok ? null : new Error('Unsupported file type'), ok);
  }
});

// ---------- MongoDB ----------
mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/edithub')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err.message));

// ---------- Models ----------
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  role: { type: String, enum: ['user', 'admin'], default: 'user' }
}, { timestamps: true });

const projectSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true, trim: true },
  description: { type: String, default: '' },
  status: { type: String, enum: ['pending', 'in_progress', 'completed'], default: 'pending' },
  files: [{
    url: String,
    originalName: String,
    mimeType: String,
    uploadedAt: { type: Date, default: Date.now }
  }],
  edits: [{
    editor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    note: String,
    fileUrl: String,
    createdAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);

// ---------- Auth helpers ----------
const auth = (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
  next();
};

// ---------- Auth routes ----------
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'All fields are required' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed });

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json(user);
});

// ---------- Project routes ----------
app.get('/api/projects', auth, async (req, res) => {
  const query = req.user.role === 'admin' ? {} : { owner: req.user.id };
  const projects = await Project.find(query)
    .populate('owner', 'name email')
    .sort({ createdAt: -1 });
  res.json(projects);
});

app.post('/api/projects', auth, async (req, res) => {
  try {
    const { title, description } = req.body;
    if (!title) return res.status(400).json({ message: 'Title is required' });

    const project = await Project.create({
      owner: req.user.id,
      title,
      description
    });
    res.status(201).json(project);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/projects/:id', auth, async (req, res) => {
  const project = await Project.findById(req.params.id).populate('owner', 'name email');
  if (!project) return res.status(404).json({ message: 'Project not found' });
  if (req.user.role !== 'admin' && String(project.owner._id) !== req.user.id) {
    return res.status(403).json({ message: 'Not allowed' });
  }
  res.json(project);
});

app.put('/api/projects/:id', auth, async (req, res) => {
  const project = await Project.findById(req.params.id);
  if (!project) return res.status(404).json({ message: 'Project not found' });
  if (req.user.role !== 'admin' && String(project.owner) !== req.user.id) {
    return res.status(403).json({ message: 'Not allowed' });
  }

  const allowed = ['title', 'description', 'status'];
  allowed.forEach(key => {
    if (req.body[key] !== undefined) project[key] = req.body[key];
  });
  await project.save();
  res.json(project);
});

app.delete('/api/projects/:id', auth, async (req, res) => {
  const project = await Project.findById(req.params.id);
  if (!project) return res.status(404).json({ message: 'Project not found' });
  if (req.user.role !== 'admin' && String(project.owner) !== req.user.id) {
    return res.status(403).json({ message: 'Not allowed' });
  }
  await project.deleteOne();
  res.json({ message: 'Project deleted' });
});

// ---------- File upload route ----------
app.post('/api/projects/:id/upload', auth, upload.array('files', 10), async (req, res) => {
  const project = await Project.findById(req.params.id);
  if (!project) return res.status(404).json({ message: 'Project not found' });
  if (req.user.role !== 'admin' && String(project.owner) !== req.user.id) {
    return res.status(403).json({ message: 'Not allowed' });
  }

  const uploaded = req.files.map(file => ({
    url: '/uploads/' + file.filename,
    originalName: file.originalname,
    mimeType: file.mimetype
  }));

  project.files.push(...uploaded);
  await project.save();
  res.status(201).json(project);
});

// ---------- Edit note route ----------
app.post('/api/projects/:id/edits', auth, async (req, res) => {
  const project = await Project.findById(req.params.id);
  if (!project) return res.status(404).json({ message: 'Project not found' });
  if (req.user.role !== 'admin' && String(project.owner) !== req.user.id) {
    return res.status(403).json({ message: 'Not allowed' });
  }

  project.edits.push({
    editor: req.user.id,
    note: req.body.note || '',
    fileUrl: req.body.fileUrl || ''
  });
  await project.save();
  res.status(201).json(project);
});

// ---------- Admin route ----------
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const users = await User.find().select('-password');
  res.json(users);
});

// ---------- Health check ----------
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'Edit Hub Backend' });
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Edit Hub backend running on http://localhost:${PORT}`);
});
