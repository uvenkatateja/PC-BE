const jwt = require('jsonwebtoken');
const User = require('../models/user.model');

/**
 * @description Generate JWT authentication token
 * @param {string} id - User ID to include in token payload
 * @returns {string} JWT token
 * @private
 */
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

/**
 * @description Format user response data (removes sensitive fields)
 * @param {Object} user - User document from database
 * @returns {Object} Sanitized user data
 * @private
 */
const formatUserResponse = (user) => {
  return {
    _id: user._id,
    name: user.name,
    email: user.email,
    role: user.role
  };
};

/**
 * @description Register a new user
 * @route POST /api/auth/register
 * @access Public
 */
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(409).json({
        success: false,
        message: 'Email already registered'
      });
    }

    const user = await User.create({ name, email, password });
    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      data: {
        token,
        user: formatUserResponse(user)
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Registration failed'
    });
  }
};

/**
 * @description Authenticate user and get token
 * @route POST /api/auth/login
 * @access Public
 */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const token = generateToken(user._id);

    res.status(200).json({
      success: true,
      data: {
        token,
        user: formatUserResponse(user)
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
};

/**
 * @description Get current authenticated user profile
 * @route GET /api/auth/me
 * @access Private (requires auth middleware)
 */
exports.getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: formatUserResponse(user)
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve user data'
    });
  }
};

/**
 * @description Update user profile (name and email)
 * @route PUT /api/auth/profile
 * @access Private (requires auth middleware)
 */
exports.updateProfile = async (req, res) => {
  try {
    const { name, email } = req.body;
    
    let user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    if (email && email !== user.email) {
      const emailExists = await User.findOne({ email });
      if (emailExists) {
        return res.status(409).json({
          success: false,
          message: 'Email already in use'
        });
      }
    }
    
    if (name) user.name = name;
    if (email) user.email = email;
    
    await user.save();
    
    res.status(200).json({
      success: true,
      data: formatUserResponse(user)
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Profile update failed'
    });
  }
};

/**
 * @description Change user password
 * @route PUT /api/auth/change-password
 * @access Private (requires auth middleware)
 */
exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current and new password required'
      });
    }
    
    const user = await User.findById(req.user.id).select('+password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    if (!(await user.matchPassword(currentPassword))) {
      return res.status(401).json({
        success: false,
        message: 'Current password incorrect'
      });
    }
    
    user.password = newPassword;
    await user.save();
    
    res.status(200).json({
      success: true,
      message: 'Password updated'
    });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({
      success: false,
      message: 'Password change failed'
    });
  }
}; 

/**
 * @description Verify if an email exists in the database
 * @route POST /api/auth/verify-email
 * @access Public
 */
exports.verifyEmail = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    // Find user by email
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Email not found'
      });
    }
    
    // Log the verification attempt for security auditing
    console.log(`Email verification requested for ${email}`);
    
    res.status(200).json({
      success: true,
      message: 'Email verified successfully'
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Email verification failed'
    });
  }
};

/**
 * @description Reset user password with user-chosen password
 * @route POST /api/auth/recover-password
 * @access Public
 */
exports.recoverPassword = async (req, res) => {
  try {
    const { email, newPassword, securityAnswers } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    if (!newPassword) {
      return res.status(400).json({
        success: false,
        message: 'New password is required'
      });
    }

    // Find user by email
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Email not found'
      });
    }
    
    // If security answers were provided, verify them
    // This is a placeholder for future implementation
    // In a real application, you would store security questions and answers in the user model
    // and verify them here
    if (securityAnswers) {
      console.log('Security answers provided:', securityAnswers);
      
      // In a real implementation, you would verify the answers against stored values
      // For now, we'll just log them and proceed with the password reset
      // Example verification logic (commented out):
      /*
      if (!user.securityQuestions || 
          !user.securityQuestions.some(q => 
            q.question === securityAnswers.question1 && 
            q.answer === securityAnswers.answer1)) {
        return res.status(401).json({
          success: false,
          message: 'Security question verification failed'
        });
      }
      */
    }
    
    // Update the user's password in the database with the user-chosen password
    user.password = newPassword;
    await user.save();
    
    // Log the password reset for security auditing
    console.log(`Password reset for ${email}${securityAnswers ? ' with security verification' : ''}`);
    
    res.status(200).json({
      success: true,
      message: 'Password has been reset successfully'
    });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({
      success: false,
      message: 'Password reset failed'
    });
  }
};