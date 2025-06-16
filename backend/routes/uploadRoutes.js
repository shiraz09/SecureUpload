import express from 'express';
import multer from 'multer';
import { requireAuth } from '../utils/authMiddleware.js';
import { uploadHandler, listAll, deleteFile, deleteAllFiles } from '../controllers/uploadController.js';

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// Public route - no authentication required
router.get('/public', (req, res) => {
  res.json({ message: 'Public files endpoint' });
});

// Protected routes - require authentication
router.post('/', requireAuth, upload.single('file'), uploadHandler);
router.get('/', requireAuth, listAll);
router.delete('/:fileId', requireAuth, deleteFile);
router.delete('/', requireAuth, deleteAllFiles);

export default router;
