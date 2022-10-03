const jwt = require('jsonwebtoken');
require('dotenv').config();

module.exports = {
  authMiddleware: function ({ req }) {
    // allows token to be sent via req.bod, req.query, or headers
    let token = req.body.token || req.query.token || req.headers.authorization;

    // separate "bearer" from "<tokenvalue>"
    if (req.headers.authorization) {
      token = token.split(' ').pop().trim();
    }

    // if no token, return request object as is
    if (!token) {
      return req;
    }

    try {
      // decode and attach user data to request object
      const { data } = jwt.verify(token, process.env.JWT_SECRET, {
        maxAge: process.env.JWT_TIMEOUT,
      });
      req.user = data;
    } catch {
      console.log('Invalid token');
    }

    // return updated request object
    return req;
  },
  signToken: function ({ username, email, _id }) {
    const payload = { username, email, _id };

    return jwt.sign({ data: payload }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_TIMEOUT,
    });
  },
};
