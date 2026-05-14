const SecurityLog = require('../models/SecurityLog');

// Brute force: 5 daqiqada 5 ta muvaffaqiyatsiz urinish
async function detectBruteForce(email, ip) {
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
  const failedAttempts = await SecurityLog.countDocuments({
    user: email,
    status: 'failed',
    action: 'Login',
    createdAt: { $gte: fiveMinutesAgo }
  });
  return failedAttempts >= 5;
}

// Replay attack: bir xil IP dan 10 soniyada 3 ta so'rov
async function detectReplayAttack(ip) {
  const tenSecondsAgo = new Date(Date.now() - 10 * 1000);
  const requests = await SecurityLog.countDocuments({
    ip,
    createdAt: { $gte: tenSecondsAgo }
  });
  return requests >= 3;
}

// Session hijacking: bir xil token boshqa IP dan ishlatilsa
async function detectSessionHijacking(email, ip) {
  const lastLog = await SecurityLog.findOne({
    user: email,
    status: 'success',
    action: 'Login'
  }).sort({ createdAt: -1 });

  if (lastLog && lastLog.ip !== ip) {
    return true;
  }
  return false;
}

module.exports = { detectBruteForce, detectReplayAttack, detectSessionHijacking };