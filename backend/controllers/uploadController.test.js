import { jest } from '@jest/globals';
import { uploadHandler, listAll, deleteFile } from './uploadController.js';

// Mock setTimeout and setInterval to prevent cleanup function from running during tests
jest.useFakeTimers();

// Mock dependencies
jest.mock('../utils/cloudinary.js', () => ({
  __esModule: true,
  default: {
    uploader: {
      upload_stream: jest.fn(),
      destroy: jest.fn()
    }
  }
}));

jest.mock('../utils/virusTotal.js', () => ({
  __esModule: true,
  scanFile: jest.fn(),
  getAnalysis: jest.fn()
}));

jest.mock('cloudinary', () => ({
  __esModule: true,
  default: {
    v2: {
      search: {
        expression: jest.fn().mockReturnThis(),
        with_field: jest.fn().mockReturnThis(),
        max_results: jest.fn().mockReturnThis(),
        execute: jest.fn()
      },
      api: {
        resource: jest.fn()
      },
      uploader: {
        destroy: jest.fn()
      }
    }
  }
}));

// Helper for mocking the request object
function mockRequest(file = null, userId = 'user123') {
  return {
    file: file || {
      buffer: Buffer.from('test file content'),
      mimetype: 'application/pdf',
      originalname: 'test.pdf',
      size: 1024
    },
    userId
  };
}

// Helper for mocking the response object
function mockResponse() {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
}

describe('Upload Controller', () => {
  // Clear all mocks before each test
  beforeEach(() => {
    jest.clearAllMocks();
    jest.clearAllTimers();
    // Silence console logs for cleaner test output
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterAll(() => {
    // Restore console functions
    console.log.mockRestore();
    console.error.mockRestore();
    jest.useRealTimers();
  });

  describe('uploadHandler', () => {
    // Test for successful upload of a clean file
    test('should successfully upload a clean file', async () => {
      // Mock dependencies
      const mockCloudinary = require('../utils/cloudinary.js').default;
      const { scanFile, getAnalysis } = require('../utils/virusTotal.js');
      
      // Setup cloudinary mock
      const mockUploadStream = jest.fn();
      mockCloudinary.uploader.upload_stream.mockImplementation((options, callback) => {
        const mockStream = {
          end: (buffer) => {
            callback(null, {
              public_id: 'test-id',
              secure_url: 'https://example.com/test-id'
            });
          }
        };
        return mockStream;
      });
      
      // Setup VirusTotal mocks
      scanFile.mockResolvedValue('scan-id-123');
      getAnalysis.mockResolvedValue({
        attributes: {
          status: 'completed',
          stats: {
            malicious: 0
          }
        }
      });
      
      // Setup request and response
      const req = mockRequest();
      const res = mockResponse();
      
      // Execute the function
      await uploadHandler(req, res);
      
      // Assertions
      expect(scanFile).toHaveBeenCalled();
      expect(getAnalysis).toHaveBeenCalled();
      expect(mockCloudinary.uploader.upload_stream).toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        originalName: 'test.pdf',
        verdict: 'clean',
        userId: 'user123'
      }));
    });

    // Test for malicious file detection
    test('should detect a malicious file and not upload it', async () => {
      // Mock dependencies
      const { scanFile, getAnalysis } = require('../utils/virusTotal.js');
      
      // Setup VirusTotal mocks for malicious file
      scanFile.mockResolvedValue('scan-id-456');
      getAnalysis.mockResolvedValue({
        attributes: {
          status: 'completed',
          stats: {
            malicious: 5  // File has malicious detections
          }
        }
      });
      
      // Setup request with malicious file
      const req = mockRequest({
        buffer: Buffer.from('malicious content'),
        mimetype: 'application/pdf',
        originalname: 'malicious.pdf',
        size: 1024
      });
      const res = mockResponse();
      
      // Execute the function
      await uploadHandler(req, res);
      
      // Assertions
      expect(scanFile).toHaveBeenCalled();
      expect(getAnalysis).toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        originalName: 'malicious.pdf',
        verdict: 'malicious',
        url: null  // No URL for malicious files
      }));
    });

    // Test for known malicious file patterns (EICAR test file)
    test('should block known malicious test files without scanning', async () => {
      // Setup request with EICAR test file name
      const req = mockRequest({
        buffer: Buffer.from('EICAR test file'),
        mimetype: 'text/plain',
        originalname: 'eicar.com.txt',
        size: 1024
      });
      const res = mockResponse();
      
      // Execute the function
      await uploadHandler(req, res);
      
      // Assertions - should detect by name without scanning
      const { scanFile } = require('../utils/virusTotal.js');
      expect(scanFile).not.toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        originalName: 'eicar.com.txt',
        verdict: 'malicious',
        url: null
      }));
    });
    
    // Test for unauthorized access (missing userId)
    test('should reject upload if user is not authenticated', async () => {
      const req = mockRequest(null, null);  // No userId
      const res = mockResponse();
      
      await uploadHandler(req, res);
      
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'User authentication required'
      }));
    });
  });

  // Tests for other functions like listAll, deleteFile, etc. can be added here
  describe('listAll', () => {
    test('should list all files for authenticated user', async () => {
      // Mock the cloudinary search API
      const mockCloudinary = require('cloudinary').default.v2;
      mockCloudinary.search.execute.mockResolvedValue({
        resources: [
          {
            public_id: 'file1',
            secure_url: 'https://example.com/file1',
            context: { 
              verdict: 'clean',
              originalName: 'test1.pdf',
              userId: 'user123'
            },
            tags: ['clean', 'user123']
          },
          {
            public_id: 'file2',
            secure_url: 'https://example.com/file2',
            context: { 
              verdict: 'malicious',
              originalName: 'test2.pdf',
              userId: 'user123'
            },
            tags: ['malicious', 'user123']
          }
        ]
      });
      
      // Setup request and response
      const req = { userId: 'user123' };
      const res = mockResponse();
      
      // Execute the function
      await listAll(req, res);
      
      // Assertions
      expect(mockCloudinary.search.expression).toHaveBeenCalledWith(`resource_type:raw AND tags:user123`);
      expect(res.json).toHaveBeenCalledWith(expect.arrayContaining([
        expect.objectContaining({
          id: 'file1',
          originalName: 'test1.pdf',
          verdict: 'clean',
          url: 'https://example.com/file1'
        }),
        expect.objectContaining({
          id: 'file2',
          originalName: 'test2.pdf',
          verdict: 'malicious',
          url: null  // Malicious file has no URL
        })
      ]));
    });
  });

  describe('deleteFile', () => {
    test('should delete a file owned by the user', async () => {
      // Mock the cloudinary API
      const mockCloudinary = require('cloudinary').default.v2;
      
      // Mock the resource check
      mockCloudinary.api.resource.mockResolvedValue({
        public_id: 'file1',
        context: { userId: 'user123' },
        tags: ['clean', 'user123']
      });
      
      // Mock the destroy function
      mockCloudinary.uploader.destroy.mockResolvedValue({ result: 'ok' });
      
      // Setup request and response
      const req = { userId: 'user123', params: { fileId: 'file1' } };
      const res = mockResponse();
      
      // Execute the function
      await deleteFile(req, res);
      
      // Assertions
      expect(mockCloudinary.api.resource).toHaveBeenCalledWith('file1', { resource_type: 'raw' });
      expect(mockCloudinary.uploader.destroy).toHaveBeenCalledWith('file1', { resource_type: 'raw' });
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        success: true
      }));
    });
    
    test('should reject deletion if user does not own the file', async () => {
      // Mock the cloudinary API
      const mockCloudinary = require('cloudinary').default.v2;
      
      // Mock the resource check for a different user's file
      mockCloudinary.api.resource.mockResolvedValue({
        public_id: 'file1',
        context: { userId: 'otherUser' },
        tags: ['clean', 'otherUser']
      });
      
      // Setup request and response
      const req = { userId: 'user123', params: { fileId: 'file1' } };
      const res = mockResponse();
      
      // Execute the function
      await deleteFile(req, res);
      
      // Assertions
      expect(mockCloudinary.uploader.destroy).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        error: expect.stringContaining('permission')
      }));
    });
  });
}); 