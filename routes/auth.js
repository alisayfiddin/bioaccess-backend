const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const SecurityLog = require('../models/SecurityLog');
const { detectBruteForce, detectReplayAttack, detectSessionHijacking } = require('../middleware/attackDetector');

// Register
router.post('/register', async (req, res) => {
  try {
    const { name, email, password, role, faceDescriptor } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Bu email allaqachon mavjud' });
    }

    if (!faceDescriptor || faceDescriptor.length === 0) {
      return res.status(400).json({ message: 'Yuz skanerlash majburiy' });
    }

    // Yuz allaqachon ro'yxatdan o'tganmi tekshirish
    const allUsers = await User.find({ faceDescriptor: { $exists: true, $ne: [] } });
    for (let u of allUsers) {
      const savedDescriptor = new Float32Array(u.faceDescriptor);
      const newDescriptor = new Float32Array(faceDescriptor);

      let sum = 0;
      for (let i = 0; i < savedDescriptor.length; i++) {
        sum += Math.pow(savedDescriptor[i] - newDescriptor[i], 2);
      }
      const distance = Math.sqrt(sum);

      if (distance < 0.6) {
        return res.status(400).json({
          message: 'Bu yuz allaqachon ro\'yxatdan o\'tgan! Faqat kirish qiling.'
        });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role, faceDescriptor });
    await user.save();

    res.status(201).json({ message: 'Foydalanuvchi yaratildi ✅' });
  } catch (err) {
    res.status(500).json({ message: 'Server xatosi', error: err.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password, faceDescriptor } = req.body;
    const ip = req.ip;

    // Replay attack
    const isReplay = await detectReplayAttack(ip);
    if (isReplay) {
      await SecurityLog.create({ user: email, action: 'Replay Attack', ip, status: 'failed' });
      return res.status(429).json({
        message: 'Juda ko\'p so\'rov! Replay attack aniqlandi.',
        attack: 'REPLAY_ATTACK'
      });
    }

    // Brute force
    const isBrute = await detectBruteForce(email, ip);
    if (isBrute) {
      await SecurityLog.create({ user: email, action: 'Brute Force Attack', ip, status: 'failed' });
      return res.status(429).json({
        message: 'Brute force attack aniqlandi! Hisob vaqtincha bloklandi.',
        attack: 'BRUTE_FORCE'
      });
    }

    // Userni topish
    const user = await User.findOne({ email });
    if (!user) {
      await SecurityLog.create({ user: email, action: 'Login', ip, status: 'failed' });
      return res.status(400).json({ message: 'Email yoki parol noto\'g\'ri' });
    }

    // Parolni tekshirish
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      await SecurityLog.create({ user: email, action: 'Login', ip, status: 'failed' });
      return res.status(400).json({ message: 'Email yoki parol noto\'g\'ri' });
    }

    // Yuz solishtirish
    if (faceDescriptor && user.faceDescriptor && user.faceDescriptor.length > 0) {
      const savedDescriptor = new Float32Array(user.faceDescriptor);
      const currentDescriptor = new Float32Array(faceDescriptor);

      let sum = 0;
      for (let i = 0; i < savedDescriptor.length; i++) {
        sum += Math.pow(savedDescriptor[i] - currentDescriptor[i], 2);
      }
      const distance = Math.sqrt(sum);

      if (distance > 0.6) {
        await SecurityLog.create({ user: email, action: 'Face Mismatch', ip, status: 'failed' });
        return res.status(401).json({ message: 'Yuz tasdiqlanmadi! Ruxsat yo\'q.' });
      }
    } else if (!faceDescriptor) {
      return res.status(400).json({ message: 'Yuz skanerlash majburiy' });
    }

    // Session hijacking
    const isHijack = await detectSessionHijacking(email, ip);
    if (isHijack) {
      await SecurityLog.create({ user: email, action: 'Session Hijacking', ip, status: 'failed' });
    }

    // JWT token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    await SecurityLog.create({ user: email, action: 'Login', ip, status: 'success' });

    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server xatosi', error: err.message });
  }
});

// Security logs
router.get('/logs', async (req, res) => {
  try {
    const logs = await SecurityLog.find().sort({ createdAt: -1 }).limit(50);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ message: 'Server xatosi' });
  }
});

// Faqat development uchun - barcha userlarni o'chirish
router.delete('/clear-users', async (req, res) => {
  try {
    await User.deleteMany({});
    res.json({ message: 'Barcha userlar o\'chirildi ✅' });
  } catch (err) {
    res.status(500).json({ message: 'Xato', error: err.message });
  }
});
// Barcha userlarni olish
router.get('/users', async (req, res) => {
  try {
    const users = await User.find({}, { password: 0, faceDescriptor: 0 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Server xatosi' });
  }
});
// Dashboard statistikasi
router.get('/stats', async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const todayLogins = await SecurityLog.countDocuments({
      action: 'Login',
      status: 'success',
      createdAt: { $gte: today }
    });

    const failedLogins = await SecurityLog.countDocuments({
      status: 'failed',
      createdAt: { $gte: today }
    });

    const totalUsers = await User.countDocuments();

    const alerts = await SecurityLog.find({
      action: { $in: ['Brute Force Attack', 'Replay Attack', 'Session Hijacking', 'Face Mismatch'] },
      createdAt: { $gte: today }
    }).sort({ createdAt: -1 }).limit(10);

    res.json({ todayLogins, failedLogins, totalUsers, alerts });
  } catch (err) {
    res.status(500).json({ message: 'Server xatosi' });
  }
});
module.exports = router;