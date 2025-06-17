import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { useApiService } from '../utils/api';

export default function FileUpload({ onUploaded }) {
  const [file, setFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const api = useApiService();

  // Add navigation warning when upload is in progress
  useEffect(() => {
    // Define function to handle beforeunload event
    const handleBeforeUnload = (e) => {
      if (isUploading) {
        // Standard way to show confirmation dialog before leaving page
        const message = 'File upload is in progress. Leaving this page will cancel the upload. Are you sure?';
        e.returnValue = message; // Required for Chrome
        return message; // For other browsers
      }
    };
    
    // Add event listener for page navigation
    window.addEventListener('beforeunload', handleBeforeUnload);
    
    // Clean up by removing event listener
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [isUploading]);

  // Function to check if a file has a known malicious pattern
  const checkMaliciousPatterns = (file) => {
    // Known malicious patterns (EICAR test files and common malware names)
    const maliciousPatterns = ['eicar', 'eicar.txt', 'eicar.com', 'eicar_com.zip', 'eicarcom2.zip'];
    
    // Check the file name for known malicious patterns
    const fileName = file.name.toLowerCase();
    return maliciousPatterns.some(pattern => fileName.includes(pattern));
  };

  // Function to check if file is too large (over 10MB)
  const isFileTooLarge = (file) => {
    const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB in bytes
    return file.size > MAX_FILE_SIZE;
  };

  const handleSubmit = async e => {
    e.preventDefault();
    if (!file) return;
    
    try {
      // Check file size on client side before uploading
      if (isFileTooLarge(file)) {
        toast.error(`File "${file.name}" is too large. Maximum size is 10MB.`, {
          style: {
            background: '#363636',
            color: '#fff',
          },
          duration: 4000
        });
        setFile(null);
        return;
      }
      
      setIsUploading(true);
      setProgress(20);
      
      // Check for known malicious files on the client side
      if (checkMaliciousPatterns(file)) {
        setProgress(100);
        toast.error('Warning: Potentially malicious file detected!', {
          style: {
            background: '#363636',
            color: '#fff',
          },
          duration: 4000
        });
        
        // Create a synthetic response for suspicious files
        // This will add it to the suspiciousFiles list without uploading
        const syntheticResponse = {
          id: `local-${Date.now()}`, // Create a unique ID
          originalName: file.name,
          url: null, // No URL since it wasn't uploaded
          verdict: 'malicious',
          timestamp: Date.now() // Add timestamp
        };
        
        // Send to the parent component to handle as suspicious
        onUploaded(syntheticResponse);
        setFile(null);
        setIsUploading(false);
        setTimeout(() => setProgress(0), 2000);
        return;
      }
      
      // Use toast for uploading notification
      const uploadToastId = toast.loading('Uploading & scanning...', {
        style: {
          background: '#363636',
          color: '#fff',
        }
      });
      
      // Also show a warning toast about not navigating away
      toast.error(
        'Please do not navigate away from this page until the upload is complete.',
        { 
          duration: 5000,
          icon: '⚠️'
        }
      );
      
      // Simulate progress during scan since we don't have real progress events
      const progressInterval = setInterval(() => {
        setProgress(prev => {
          const newProgress = Math.min(prev + 10, 90);
          return newProgress;
        });
      }, 700);
      
      try {
        // Use our API service instead of direct fetch
        const responseData = await api.uploadFile(file);
        
        // Ensure the response includes a timestamp
        const responseWithTimestamp = {
          ...responseData,
          timestamp: Date.now() // Add current timestamp to ensure uniqueness
        };
        
        setProgress(100);
        
        // Update toast based on verdict
        if (responseWithTimestamp.verdict === 'clean') {
          toast.success('File verified as safe', { id: uploadToastId });
        } else {
          toast.error('Warning: File may be malicious', { id: uploadToastId });
        }
        
        onUploaded(responseWithTimestamp);
        setFile(null); // Clear the file input after successful upload
      } catch (apiError) {
        console.error('Upload API error:', apiError);
        toast.error(`Upload failed: ${apiError.message || 'Unknown error'}`, { 
          id: uploadToastId,
          duration: 5000
        });
      } finally {
        clearInterval(progressInterval);
      }
    } catch (err) {
      console.error('Upload error:', err);
      toast.error(`Upload failed: ${err.message || 'Unknown error'}`, {
        duration: 5000
      });
    } finally {
      setIsUploading(false);
      // Reset progress after a short delay
      setTimeout(() => {
        setProgress(0);
      }, 2000);
    }
  };
  
  const handleFileChange = e => {
    if (e.target.files[0]) {
      const selectedFile = e.target.files[0];
      
      // Show warning immediately if file is too large
      if (isFileTooLarge(selectedFile)) {
        toast.error(`File "${selectedFile.name}" is too large. Maximum size is 10MB.`, {
          duration: 4000,
          style: {
            background: '#363636',
            color: '#fff',
          }
        });
        // Still set the file so user sees the name, but they'll get an error on submit
      }
      
      setFile(selectedFile);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6 bg-white rounded-lg border border-gray-200 p-6">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Select file to scan
        </label>
        <div className="flex items-center space-x-2">
          <label className="cursor-pointer flex-grow">
            <div className="px-4 py-3 bg-gray-50 text-sm rounded-lg border border-dashed border-gray-300 hover:bg-gray-100 hover:border-gray-400 transition-colors">
              {file ? file.name : 'Click to browse files'}
            </div>
            <input 
              type="file" 
              onChange={handleFileChange} 
              className="hidden"
            />
          </label>
          <button 
            type="submit" 
            className="px-4 py-2 rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            disabled={!file || isUploading || (file && isFileTooLarge(file))}
          >
            {isUploading ? 'Processing...' : 'Upload & Scan'}
          </button>
        </div>
        {file && isFileTooLarge(file) && (
          <p className="mt-2 text-sm text-red-600">
            File exceeds maximum size (10MB). Please select a smaller file.
          </p>
        )}
      </div>
      
      {isUploading && (
        <>
          <div className="space-y-2">
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-indigo-600 h-2 rounded-full transition-all duration-300 ease-out"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
            <p className="text-xs text-gray-500 text-right">{progress}%</p>
          </div>
          
          {/* Upload warning message */}
          <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-yellow-800">Upload in Progress</h3>
                <div className="mt-1 text-sm text-yellow-700">
                  <p>Please do not leave or refresh this page until the upload is complete.</p>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </form>
  );
}
