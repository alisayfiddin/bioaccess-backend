const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

// Test route
app.get('/', (req, res) => {
  res.json({ message: 'BioAccess Backend ishlayapti! ✅' });
});

// MongoDB ulanish
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('MongoDB ulandi ✅');
    app.listen(process.env.PORT, () => {
      console.log(`Server ${process.env.PORT} portda ishlayapti ✅`);
    });
  })
  .catch((err) => {
    console.log('MongoDB ulanmadi ❌', err.message);
  });