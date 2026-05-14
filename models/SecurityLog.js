const mongoose = require('mongoose');

const SecurityLogSchema = new mongoose.Schema({
  user: {
    type: String,
    required: true,
  },
  action: {
    type: String,
    required: true,
  },
  ip: {
    type: String,
    required: true,
  },
  status: {
    type: String,
    enum: ['success', 'failed'],
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('SecurityLog', SecurityLogSchema);
