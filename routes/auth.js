// routes/auth.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { auth, checkRole } = require('../middleware/auth');

router.post('/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    if (!['admin', 'teacher', 'student'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const user = new User({
      username,
      email,
      password,
      role
    });

    await user.save();

    const token = jwt.sign(
      { userId: user._id },
      'your_jwt_secret_key',
      { expiresIn: '24h' }
    );

    res.status(201).json({ user, token });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid login credentials' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid login credentials' });
    }

    const token = jwt.sign(
      { userId: user._id },
      'your_jwt_secret_key',
      { expiresIn: '24h' }
    );

    res.json({ user, token });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.get('/admin', auth, checkRole(['admin']), async (req, res) => {
  try {
    const users = await User.find({}, '-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user by ID
router.get('/admin/:id', auth, checkRole(['admin']), async (req, res) => {
  try {
    const user = await User.findById(req.params.id, '-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update user
router.put('/admin/:id', auth, checkRole(['admin']), async (req, res) => {
  try {
    const { username, email, role } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { username, email, role },
      { new: true, runValidators: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Delete user
router.delete('/admin/:id', auth, checkRole(['admin']), async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }

});

router.get('/teacher', auth, checkRole(['admin', 'teacher']), (req, res) => {
  res.json({ message: 'Teacher access granted' });
});

router.get('/student', auth, checkRole(['admin', 'teacher', 'student']), (req, res) => {
  res.json({ message: 'Student access granted' });
});

module.exports = router;