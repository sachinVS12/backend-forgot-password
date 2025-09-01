const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Signup
const signup = async (req, res) => {
  const { email, password } = req.body;

  try {
    const userExist = await User.findOne({ email });
    if (userExist) return res.status(400).json({ message: 'User already exists' });

    const newUser = new User({ email, password });
    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Login
const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await user.matchPassword(password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Forgot Password
const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    // Generate a reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpire = Date.now() + 3600000; // Token expires in 1 hour
    await user.save();

    // Generate the reset password URL
    const resetUrl = `http://localhost:5000/reset-password/${resetToken}`;

    // Create transporter using Nodemailer (Gmail)
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Configure email options
    const mailOptions = {
      to: user.email,
      subject: 'Password Reset Request',
      text: `Click the link to reset your password: ${resetUrl}`,
    };

    // Send the reset password email
    await transporter.sendMail(mailOptions);

    res.json({ message: 'Password reset email sent' });
  } catch (err) {
    console.error("Error in forgotPassword:", err); // Log the error to console
    res.status(500).json({ message: 'Server error', error: err.message }); // Return error details in response
  }
};


// Reset Password
// Reset Password function
const resetPassword = async (req, res) => {
  const { resetToken, newPassword } = req.body;  // Get reset token and new password from body

  try {
    // Step 1: Find user with the provided token and check if it's expired
    const user = await User.findOne({
      resetPasswordToken: resetToken,
      resetPasswordExpire: { $gt: Date.now() },  // Token must not be expired
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    // Step 2: Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);  // Hash the password with bcrypt

    // Step 3: Update user password and clear reset token fields
    user.password = hashedPassword;  // Save hashed password
    user.resetPasswordToken = undefined;  // Clear reset token
    user.resetPasswordExpire = undefined;  // Clear token expiration

    await user.save();  // Save the updated user

    // Step 4: Send success response
    res.json({ message: 'Password has been reset successfully!' });
  } catch (err) {
    console.error('Error in resetPassword:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = { signup, login, forgotPassword, resetPassword };
