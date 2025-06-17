import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { ClerkExpressWithAuth } from '@clerk/clerk-sdk-node';
import uploadRoutes from './routes/uploadRoutes.js';

dotenv.config();
const app = express();

// _Set Clerk secret key from environment variables
const clerkSecretKey = process.env.CLERK_SECRET_KEY;
if (!clerkSecretKey) {
  console.error('CLERK_SECRET_KEY is missing in environment variables');
  process.exit(1);
}

app.use(cors());
app.use(express.json());

// Apply Clerk middleware globally
app.use(ClerkExpressWithAuth());

// Use authentication for API routes
app.use('/api/files', uploadRoutes);

const port = process.env.PORT || 5000;
app.listen(port, () => console.log(`API running on http://localhost:${port}`));
