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

  const fetchFiles = async () => {
    if (!authLoaded) return;
    
    setLoading(true);
    try {
      const allFiles = await api.listFiles();
      console.log('All files from API:', allFiles);
      
      // Filter out malicious files or files with no URL (meaning they weren't uploaded to Cloudinary)
      const cleanFiles = allFiles.filter(file => 
        file.verdict === 'clean' && file.url !== null
      );
      
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
      // Check if the file exists in localStorage's recently uploaded files
      const storedFilesStr = localStorage.getItem('recentlyUploadedCleanFiles');
      if (storedFilesStr) {
        const storedFiles = JSON.parse(storedFilesStr);
        
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
          
          console.log(`File ${fileId} removed from localStorage`);
          return true;
        }
      }
      return false;
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
          
          // Clear localStorage of all clean files
          localStorage.removeItem('recentlyUploadedCleanFiles');
          localStorage.removeItem('recentlyUploadedCleanFilesTime');
          
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
