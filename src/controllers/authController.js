require('dotenv').config();
const {generateUniqueValue} = require('../util/generateUniqueName');
const jwt = require('jsonwebtoken');
const User = require('../models/user'); // Your User model
const { UserDetail } = require('otpless-node-js-auth-sdk');

// Helper to generate a JWT
const generateJWTToken = (userId) => {
  const JWT_EXPIRATION_Value = process.env.JWT_EXPIRATION || '180d'
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: JWT_EXPIRATION_Value, // e.g., '1d' for 1 day
  });
};

// Step 1: Send OTP
const sendOTP = async (req, res) => {
  try {
    const { mobileNumber } = req.body;

    if (!mobileNumber || !/^\d{10}$/.test(mobileNumber)) {
      return res.status(400).json({ message: 'Invalid mobile number' });
    }

    const email = process.env.OTPLESS_EMAIL;
    const channel = process.env.OTPLESS_CHANNEL;
    const hash = process.env.OTPLESS_TOKEN_ID;
    const orderId = generateUniqueValue();
    const expiry=process.env.OTPLESS_EXPIRY;
    const otpLength=process.env.OTPLESS_OTP_LENGTH;
    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;
    
    const phoneNumber = "+91"+mobileNumber;

    console.log('Sending OTP with:', {
      phoneNumber,
      channel,
      hash,
      orderId,
      expiry,
      otpLength
    });

    const response = await UserDetail.sendOTP(
      phoneNumber, 
      email, 
      channel, 
      hash, 
      orderId, 
      expiry, 
      otpLength, 
      clientId, 
      clientSecret
    );

    console.log('OTP send response:', response);

    return res.status(200).json({ 
      message: 'OTP sent successfully',
      response: { orderId }
    });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ error: error.message });
  }
};

// Step 2: Verify OTP and Login
const verifyOTPAndLogin = async (req, res) => {
  try {
    const {mobileNumber, otp, orderId} = req.body; 
    console.log('Verifying OTP for:', { mobileNumber, orderId });

    if (!mobileNumber || !otp || !orderId) {
      return res.status(400).json({ 
        message: 'Mobile number, OTP, and orderId are required'
      });
    }

    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;
    const phoneNumber = "+91"+mobileNumber;

    try {
      console.log('Calling OTPless verify with:', {
        phoneNumber,
        orderId,
        clientId: clientId ? 'present' : 'missing',
        clientSecret: clientSecret ? 'present' : 'missing'
      });

      const verifyResponse = await UserDetail.verifyOTP(
        "", 
        phoneNumber, 
        orderId, 
        otp, 
        clientId, 
        clientSecret
      );

      console.log('Verify response:', verifyResponse);

      if (!verifyResponse || !verifyResponse.isOTPVerified) {
        return res.status(400).json({ 
          message: 'Invalid OTP'
        });
      }

      // Find or create user in the database
      let user = await User.findOne({ mobileNumber });
      if (!user) {
        console.log('Creating new user for:', mobileNumber);
        user = new User({ mobileNumber });
        await user.save();
      }

      // Generate JWT
      const token = generateJWTToken(user._id);
      console.log('Login successful for user:', mobileNumber);

      return res.status(200).json({
        status: 'success',
        token,
        userStatus: user.status || 'In Progress',
        message: 'Login successful'
      });
    } catch (verifyError) {
      console.error('OTP verification failed:', verifyError);
      return res.status(400).json({ 
        message: 'OTP verification failed',
        error: verifyError.message
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ 
      message: 'Server error during login',
      error: error.message
    });
  }
};

// Step 3: Middleware to Authenticate Requests
const authenticateRequest = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied, token missing!' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = decoded; // Attach user to request object
    next();
  });
};

module.exports = {
  sendOTP,
  verifyOTPAndLogin,
  authenticateRequest,
};
