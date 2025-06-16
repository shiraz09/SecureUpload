import { clerkClient } from '@clerk/clerk-sdk-node';

export const requireAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authentication required' });
    }
    
    const token = authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    try {
      // Validate the token with Clerk
      const { sub, sid } = await clerkClient.verifyToken(token);
      
      if (!sub) {
        return res.status(401).json({ message: 'Invalid token: missing user ID' });
      }
      
      // Add user ID to request
      req.userId = sub;
      req.sessionId = sid;
      
      // Debugging log
      console.log(`Authenticated request from user: ${sub}, session: ${sid || 'unknown'}`);
      
      // Continue to the next middleware or route handler
      next();
    } catch (error) {
      console.error('Token verification error:', error.message);
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
  } catch (error) {
    console.error('Authentication error:', error.message);
    return res.status(500).json({ message: 'Authentication server error' });
  }
}; 