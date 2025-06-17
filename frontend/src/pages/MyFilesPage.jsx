import { useEffect, useState } from 'react';
import toast, { Toaster } from 'react-hot-toast';
import FileTable from '../components/FileTable';
import { useApiService } from '../utils/api';
import { useAuth } from '@clerk/clerk-react';

export default function MyFilesPage() {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const { isLoaded: authLoaded } = useAuth();
  const api = useApiService();
  const { userId } = useAuth();

  const fetchFiles = async () => {
    if (!authLoaded) return;
    
    setLoading(true);
    try {
      const allFiles = await api.listFiles();
      console.log('All files from API:', allFiles);
      
      // Filter out malicious files or files with no URL (meaning they weren't uploaded to Cloudinary)
      const cleanFiles = allFiles
        .filter(file => file.verdict === 'clean' && file.url !== null)
        .map(file => {
          // Extract timestamp from Cloudinary URL if available
          let timestamp = file.timestamp;
          
          if (!timestamp) {
            // Try to extract timestamp from file ID or URL (Cloudinary URLs contain version which is a timestamp)
            if (file.url) {
              const versionMatch = file.url.match(/\/v(\d+)\//);
              if (versionMatch && versionMatch[1]) {
                timestamp = parseInt(versionMatch[1]) * 1000; // Convert to milliseconds
              }
            }
            
            // If still no timestamp, use creation date from ID or current time
            if (!timestamp && file.id) {
              const uuidTimestamp = file.id.split('-')[0];
              if (uuidTimestamp && !isNaN(Number(uuidTimestamp))) {
                timestamp = Number(uuidTimestamp);
              } else {
                timestamp = Date.now(); // Fallback to current time
              }
            } else if (!timestamp) {
              timestamp = Date.now();
            }
          }
          
          return {
            ...file,
            timestamp
          };
        });
      
      setFiles(cleanFiles);
      console.log('Clean files to display:', cleanFiles);
    } catch (err) {
      console.error('Error fetching files:', err);
      setError('Could not load files. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (authLoaded) {
      fetchFiles();
    }
  }, [authLoaded]);

  // Function to remove a file from localStorage if it exists there
  const removeFromLocalStorage = (fileId) => {
    try {
      // Check for user-specific localStorage
      if (userId) {
        // User-specific keys
        const userCleanFilesKey = `user_${userId}_recentlyUploadedCleanFiles`;
        const userCleanTimeKey = `user_${userId}_recentlyUploadedCleanFilesTime`;
        const userSuspiciousFilesKey = `user_${userId}_recentlyUploadedSuspiciousFiles`;
        const userSuspiciousTimeKey = `user_${userId}_recentlyUploadedSuspiciousFilesTime`;
        
        // Check clean files
        const storedUserCleanFilesStr = localStorage.getItem(userCleanFilesKey);
        if (storedUserCleanFilesStr) {
          const storedFiles = JSON.parse(storedUserCleanFilesStr);
          const fileExists = storedFiles.some(file => file.id === fileId);
          
          if (fileExists) {
            // Remove the file from the array
            const updatedFiles = storedFiles.filter(file => file.id !== fileId);
            
            // Update localStorage or remove if empty
            if (updatedFiles.length > 0) {
              localStorage.setItem(userCleanFilesKey, JSON.stringify(updatedFiles));
            } else {
              localStorage.removeItem(userCleanFilesKey);
              localStorage.removeItem(userCleanTimeKey);
            }
            
            console.log(`File ${fileId} removed from user-specific clean localStorage`);
          }
        }
        
        // Check suspicious files
        const storedUserSuspiciousFilesStr = localStorage.getItem(userSuspiciousFilesKey);
        if (storedUserSuspiciousFilesStr) {
          const storedFiles = JSON.parse(storedUserSuspiciousFilesStr);
          const fileExists = storedFiles.some(file => file.id === fileId);
          
          if (fileExists) {
            // Remove the file from the array
            const updatedFiles = storedFiles.filter(file => file.id !== fileId);
            
            // Update localStorage or remove if empty
            if (updatedFiles.length > 0) {
              localStorage.setItem(userSuspiciousFilesKey, JSON.stringify(updatedFiles));
            } else {
              localStorage.removeItem(userSuspiciousFilesKey);
              localStorage.removeItem(userSuspiciousTimeKey);
            }
            
            console.log(`File ${fileId} removed from user-specific suspicious localStorage`);
          }
        }
      }
      
      // Also check legacy localStorage (for backwards compatibility)
      const storedCleanFilesStr = localStorage.getItem('recentlyUploadedCleanFiles');
      if (storedCleanFilesStr) {
        const storedFiles = JSON.parse(storedCleanFilesStr);
        
        // Check if the file with the given ID exists in localStorage
        const fileExists = storedFiles.some(file => file.id === fileId);
        
        if (fileExists) {
          // Remove the file from the array
          const updatedFiles = storedFiles.filter(file => file.id !== fileId);
          
          // Update localStorage or remove if empty
          if (updatedFiles.length > 0) {
            localStorage.setItem('recentlyUploadedCleanFiles', JSON.stringify(updatedFiles));
          } else {
            localStorage.removeItem('recentlyUploadedCleanFiles');
            localStorage.removeItem('recentlyUploadedCleanFilesTime');
          }
          
          console.log(`File ${fileId} removed from legacy localStorage`);
        }
      }
      
      return true;
    } catch (err) {
      console.error('Error removing file from localStorage:', err);
      return false;
    }
  };

  const handleDeleteFile = async (fileId) => {
    toast.promise(
      (async () => {
        setDeleting(true);
        try {
          await api.deleteFile(fileId);
          
          // Remove the deleted file from state
          setFiles(files.filter(file => file.id !== fileId));
          
          // Also remove from localStorage if it exists there
          removeFromLocalStorage(fileId);
          
          return true;
        } finally {
          setDeleting(false);
        }
      })(),
      {
        loading: 'Deleting file...',
        success: 'File deleted successfully!',
        error: 'Failed to delete file'
      }
    );
  };

  const handleDeleteAllFiles = () => {
    toast(
      (t) => (
        <div className="flex flex-col space-y-2">
          <p>Are you sure you want to delete ALL files? This action cannot be undone.</p>
          <div className="flex justify-end space-x-2">
            <button
              onClick={() => {
                toast.dismiss(t.id);
                performDeleteAll();
              }}
              className="px-3 py-1 text-white bg-red-600 rounded hover:bg-red-700"
            >
              Delete All
            </button>
            <button
              onClick={() => toast.dismiss(t.id)}
              className="px-3 py-1 bg-gray-200 rounded hover:bg-gray-300"
            >
              Cancel
            </button>
          </div>
        </div>
      ),
      { duration: 6000 }
    );
  };

  const performDeleteAll = async () => {
    toast.promise(
      (async () => {
        setDeleting(true);
        try {
          // Use our api service instead of direct fetch
          await api.deleteAllFiles();
          
          // Clear the files state
          setFiles([]);
          
          // Clear both legacy and user-specific localStorage
          localStorage.removeItem('recentlyUploadedCleanFiles');
          localStorage.removeItem('recentlyUploadedCleanFilesTime');
          
          // Clear user-specific localStorage if userId is available
          if (userId) {
            localStorage.removeItem(`user_${userId}_recentlyUploadedCleanFiles`);
            localStorage.removeItem(`user_${userId}_recentlyUploadedCleanFilesTime`);
            localStorage.removeItem(`user_${userId}_recentlyUploadedSuspiciousFiles`);
            localStorage.removeItem(`user_${userId}_recentlyUploadedSuspiciousFilesTime`);
            console.log('Cleared user-specific localStorage for file lists');
          }
          
          return true;
        } finally {
          setDeleting(false);
        }
      })(),
      {
        loading: 'Deleting all files...',
        success: 'All files deleted successfully!',
        error: 'Failed to delete all files'
      }
    );
  };

  return (
    <div className="max-w-7xl mx-auto py-10 px-4 sm:px-6 lg:px-8">
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 3000,
          style: {
            background: '#363636',
            color: '#fff',
          },
        }}
      />
      <div className="bg-white shadow-sm rounded-lg p-6">
        <div className="flex items-center justify-between border-b border-gray-200 pb-6 mb-6">
          <h1 className="text-3xl font-bold text-gray-900">Safe Files</h1>
          <div className="flex items-center space-x-2">
            <span className="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-800">
              Verified Clean
            </span>
            {files.length > 0 && (
              <button
                onClick={handleDeleteAllFiles}
                disabled={deleting}
                className="px-3 py-1 text-sm text-red-600 border border-red-300 rounded-md hover:bg-red-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {deleting ? 'Deleting...' : 'Delete All'}
              </button>
            )}
          </div>
        </div>
        
        {loading && (
          <div className="flex justify-center py-10">
            <div className="animate-spin rounded-full h-10 w-10 border-4 border-indigo-500 border-t-transparent"></div>
          </div>
        )}
        
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-800 rounded-lg p-4 mb-6">
            {error}
          </div>
        )}
        
        {!loading && !error && (
          <>
            {files.length === 0 && (
              <div className="bg-blue-50 border border-blue-200 text-blue-800 rounded-lg p-4 mb-6">
                No safe files found. Upload new files to see them here.
              </div>
            )}
            <FileTable 
              files={files} 
              onDelete={handleDeleteFile} 
              showDeleteButton={true}
            />
          </>
        )}
      </div>
    </div>
  );
}
