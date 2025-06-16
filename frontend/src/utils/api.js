import { useAuth } from '@clerk/clerk-react';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001/api';

export const useApiService = () => {
  const { getToken } = useAuth();
  
  const fetchWithAuth = async (endpoint, options = {}) => {
    // Get the token from Clerk
    const token = await getToken();
    
    // Set up default headers
    const headers = {
      ...options.headers,
    };
    
    // Add auth token if available
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    
    // Make the request
    const response = await fetch(`${API_URL}${endpoint}`, {
      ...options,
      headers,
    });
    
    // Handle non-successful responses
    if (!response.ok) {
      const error = await response.json().catch(() => ({
        message: `HTTP error ${response.status}`,
      }));
      throw new Error(error.message || 'Something went wrong');
    }
    
    // Return the response data
    return response.json();
  };
  
  // API methods
  return {
    // Files
    uploadFile: async (file, metadata = {}) => {
      const formData = new FormData();
      formData.append('file', file);
      
      if (metadata) {
        formData.append('metadata', JSON.stringify(metadata));
      }
      
      return fetchWithAuth('/files', {
        method: 'POST',
        body: formData,
      });
    },
    
    listFiles: async () => {
      return fetchWithAuth('/files');
    },
    
    deleteFile: async (fileId) => {
      return fetchWithAuth(`/files/${fileId}`, {
        method: 'DELETE',
      });
    },
    
    deleteAllFiles: async () => {
      return fetchWithAuth('/files', {
        method: 'DELETE',
      });
    },
    
    // Add more API methods as needed
  };
};