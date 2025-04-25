const jwt = require('jsonwebtoken');
const User = require('../models/user.model');

/**
 * @description Middleware to protect routes - verify token and authorize user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void}
 */
exports.protect = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization?.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required to access this resource'
      });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const currentUser = await User.findById(decoded.id);

      if (!currentUser) {
        return res.status(401).json({
          success: false,
          message: 'User no longer exists'
        });
      }

      if (currentUser.passwordChangedAfter && currentUser.passwordChangedAfter(decoded.iat)) {
        return res.status(401).json({
          success: false,
          message: 'Password recently changed, please login again'
        });
      }

      req.user = currentUser;
      next();
    } catch (error) {
      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      } else if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: 'Token expired'
        });
      }
      
      return res.status(401).json({
        success: false,
        message: 'Authentication failed'
      });
    }
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during authentication'
    });
  }
};

/**
 * @description Middleware to restrict access to specific user roles
 * @param {...String} roles - Roles allowed to access the route
 * @returns {Function} Express middleware function
 */
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Permission denied'
      });
    }
    next();
  };
};

/**
 * @description Middleware to check if user is accessing their own resource
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @param {String} paramIdField - Request parameter field containing resource ID (default: 'id')
 * @returns {void}
 */
exports.isResourceOwner = (paramIdField = 'id') => {
  return (req, res, next) => {
    const resourceId = req.params[paramIdField];
    
    if (req.user.role === 'admin') return next();
    
    if (req.user.id !== resourceId) {
      return res.status(403).json({
        success: false,
        message: 'Permission denied for this resource'
      });
    }
    
    next();
  };
}; 