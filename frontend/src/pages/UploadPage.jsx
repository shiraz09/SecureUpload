import { useState, useEffect } from 'react';
import toast, { Toaster } from 'react-hot-toast';
import FileUpload from '../components/FileUpload';
import FileTable from '../components/FileTable';
import { useAuth } from '@clerk/clerk-react';

export default function UploadPage() {
  const [cleanFiles, setCleanFiles] = useState([]);
  const [suspiciousFiles, setSuspiciousFiles] = useState([]);
  const { userId } = useAuth();
  
  // Get localStorage keys specific to this user
  const getLocalStorageKeys = (userId) => {
    return {
      cleanFiles: `user_${userId}_recentlyUploadedCleanFiles`,
      cleanTime: `user_${userId}_recentlyUploadedCleanFilesTime`,
      suspiciousFiles: `user_${userId}_recentlyUploadedSuspiciousFiles`,
      suspiciousTime: `user_${userId}_recentlyUploadedSuspiciousFilesTime`
    };
  };
  
  // Load files from localStorage on component mount or when userId changes
  useEffect(() => {
    if (userId) {
      loadFilesFromStorage();
    }
  }, [userId]);
  
  // Function to load files from localStorage
  const loadFilesFromStorage = () => {
    if (!userId) return;
    
    const keys = getLocalStorageKeys(userId);
    
    // Load clean files
    const storedCleanFiles = localStorage.getItem(keys.cleanFiles);
    const storedCleanTime = localStorage.getItem(keys.cleanTime);
    
    // Load suspicious files
    const storedSuspiciousFiles = localStorage.getItem(keys.suspiciousFiles);
    const storedSuspiciousTime = localStorage.getItem(keys.suspiciousTime);
    
    const fifteenMinutesInMs = 15 * 60 * 1000;
    const now = Date.now();
    
    try {
      // Process clean files
      if (storedCleanFiles && storedCleanTime) {
        const timeDiff = now - parseInt(storedCleanTime);
        if (timeDiff < fifteenMinutesInMs) {
          setCleanFiles(JSON.parse(storedCleanFiles));
        } else {
          localStorage.removeItem(keys.cleanFiles);
          localStorage.removeItem(keys.cleanTime);
        }
      }
      
      // Process suspicious files
      if (storedSuspiciousFiles && storedSuspiciousTime) {
        const timeDiff = now - parseInt(storedSuspiciousTime);
        if (timeDiff < fifteenMinutesInMs) {
          setSuspiciousFiles(JSON.parse(storedSuspiciousFiles));
        } else {
          localStorage.removeItem(keys.suspiciousFiles);
          localStorage.removeItem(keys.suspiciousTime);
        }
      }
    } catch (err) {
      console.error('Error loading files from localStorage:', err);
    }
  };
  
  // Function to handle new file uploads
  const handleNewUpload = (newFile) => {
    if (!userId) return;
    
    // Always check verdict and URL to determine if file is malicious
    // A file is malicious if: 
    // 1. It has a 'malicious' verdict OR
    // 2. It has no URL (which means backend blocked it)
    if (newFile.verdict === 'malicious' || !newFile.url) {
      // Handle suspicious file
      const updatedSuspicious = [newFile, ...suspiciousFiles];
      setSuspiciousFiles(updatedSuspicious);
      saveSuspiciousFilesToStorage(updatedSuspicious);
      toast.error(`File "${newFile.originalName}" detected as potentially malicious!`, {
        duration: 5000,
      });
    } else {
      // Handle clean file
      const updatedClean = [newFile, ...cleanFiles];
      setCleanFiles(updatedClean);
      saveCleanFilesToStorage(updatedClean);
    }
  };
  
  // Function to save clean files to localStorage
  const saveCleanFilesToStorage = (filesToSave) => {
    if (!userId) return;
    
    try {
      const keys = getLocalStorageKeys(userId);
      localStorage.setItem(keys.cleanFiles, JSON.stringify(filesToSave));
      localStorage.setItem(keys.cleanTime, Date.now().toString());
    } catch (err) {
      console.error('Error saving clean files to localStorage:', err);
    }
  };
  
  // Function to save suspicious files to localStorage
  const saveSuspiciousFilesToStorage = (filesToSave) => {
    if (!userId) return;
    
    try {
      const keys = getLocalStorageKeys(userId);
      localStorage.setItem(keys.suspiciousFiles, JSON.stringify(filesToSave));
      localStorage.setItem(keys.suspiciousTime, Date.now().toString());
    } catch (err) {
      console.error('Error saving suspicious files to localStorage:', err);
    }
  };
  
  // Function to clear all clean files from localStorage
  const clearCleanFilesFromStorage = () => {
    if (!userId) return;
    
    const keys = getLocalStorageKeys(userId);
    localStorage.removeItem(keys.cleanFiles);
    localStorage.removeItem(keys.cleanTime);
    setCleanFiles([]);
    toast.success('Clean files cleared');
  };
  
  // Function to clear all suspicious files from localStorage
  const clearSuspiciousFilesFromStorage = () => {
    if (!userId) return;
    
    const keys = getLocalStorageKeys(userId);
    localStorage.removeItem(keys.suspiciousFiles);
    localStorage.removeItem(keys.suspiciousTime);
    setSuspiciousFiles([]);
    toast.success('Suspicious files cleared');
  };
  
  // Function to handle clearing all recently uploaded clean files
  const handleClearClean = () => {
    toast(
      (t) => (
        <div className="flex flex-col space-y-2">
          <p>Clear all recently uploaded files?</p>
          <div className="flex justify-end space-x-2">
            <button
              onClick={() => {
                toast.dismiss(t.id);
                clearCleanFilesFromStorage();
              }}
              className="px-3 py-1 text-white bg-red-600 rounded hover:bg-red-700"
            >
              Clear All
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
  
  // Function to handle clearing all recently uploaded suspicious files
  const handleClearSuspicious = () => {
    toast(
      (t) => (
        <div className="flex flex-col space-y-2">
          <p>Clear all recently suspicious files?</p>
          <div className="flex justify-end space-x-2">
            <button
              onClick={() => {
                toast.dismiss(t.id);
                clearSuspiciousFilesFromStorage();
              }}
              className="px-3 py-1 text-white bg-red-600 rounded hover:bg-red-700"
            >
              Clear All
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
  
  // Function to delete a single clean file
  const handleDeleteCleanFile = (fileId) => {
    if (!userId) return;
    
    // Create a promise toast for deleting from recently uploaded list
    toast.promise(
      (async () => {
        const updatedFiles = cleanFiles.filter(file => file.id !== fileId);
        setCleanFiles(updatedFiles);
        
        // Update localStorage
        if (updatedFiles.length > 0) {
          saveCleanFilesToStorage(updatedFiles);
        } else {
          clearCleanFilesFromStorage();
        }
        
        return true; // Resolve the promise
      })(),
      {
        loading: 'Removing from list...',
        success: 'Removed from recently uploaded list',
        error: 'Failed to remove file'
      }
    );
  };
  
  // Function to delete a single suspicious file
  const handleDeleteSuspiciousFile = (fileId) => {
    if (!userId) return;
    
    // Create a promise toast for deleting from suspicious list
    toast.promise(
      (async () => {
        const updatedFiles = suspiciousFiles.filter(file => file.id !== fileId);
        setSuspiciousFiles(updatedFiles);
        
        // Update localStorage
        if (updatedFiles.length > 0) {
          saveSuspiciousFilesToStorage(updatedFiles);
        } else {
          clearSuspiciousFilesFromStorage();
        }
        
        return true; // Resolve the promise
      })(),
      {
        loading: 'Removing from suspicious list...',
        success: 'Removed from suspicious files list',
        error: 'Failed to remove file'
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
        <div className="border-b border-gray-200 pb-6 mb-6">
          <h1 className="text-3xl font-bold text-gray-900">Secure Upload</h1>
          <p className="mt-2 text-sm text-gray-500">
            Files are scanned for viruses and malware before being securely stored.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-8">
          <div>
            <h2 className="text-lg font-medium text-gray-900 mb-4">Upload New File</h2>
            <FileUpload onUploaded={handleNewUpload}/>
          </div>
          
          <div className="border-t pt-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-medium text-gray-900">Recently Uploaded</h2>
              {cleanFiles.length > 0 && (
                <button
                  onClick={handleClearClean}
                  className="px-3 py-1 text-sm text-red-600 border border-red-300 rounded-md hover:bg-red-50"
                >
                  Clear All
                </button>
              )}
            </div>
            
            {cleanFiles.length > 0 ? (
              <FileTable 
                files={cleanFiles} 
                onDelete={handleDeleteCleanFile} 
                showDeleteButton={true}
              />
            ) : (
              <div className="bg-gray-50 rounded-lg p-6 text-center">
                <p className="text-gray-500">No files uploaded yet</p>
              </div>
            )}
          </div>
          
          <div className="border-t pt-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center">
                <h2 className="text-lg font-medium text-gray-900 mr-2">Recently Suspicious</h2>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                  Warning
                </span>
              </div>
              {suspiciousFiles.length > 0 && (
                <button
                  onClick={handleClearSuspicious}
                  className="px-3 py-1 text-sm text-red-600 border border-red-300 rounded-md hover:bg-red-50"
                >
                  Clear All
                </button>
              )}
            </div>
            
            {suspiciousFiles.length > 0 ? (
              <div>
                <div className="mb-4 bg-yellow-50 border-l-4 border-yellow-400 p-4">
                  <div className="flex">
                    <div className="ml-3">
                      <p className="text-sm text-yellow-700">
                        Warning: These files were flagged as potentially malicious. They have not been saved to the cloud.
                      </p>
                    </div>
                  </div>
                </div>
                <FileTable 
                  files={suspiciousFiles}
                  onDelete={handleDeleteSuspiciousFile}
                  showDeleteButton={true}
                />
              </div>
            ) : (
              <div className="bg-gray-50 rounded-lg p-6 text-center">
                <p className="text-gray-500">No suspicious files detected</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
