export default function FileTable({ files, onDelete, showDeleteButton = false }) {
  if (files.length === 0) {
    return (
      <div className="mt-6 p-8 text-center bg-gray-50 rounded-xl border border-gray-100 shadow-sm">
        <p className="text-gray-500">No files found</p>
      </div>
    );
  }

  // Function to format timestamp to display date and time
  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    
    try {
      const date = new Date(timestamp);
      
      // Check if date is valid
      if (isNaN(date.getTime())) {
        return 'N/A';
      }
      
      // Format: "DD/MM/YYYY at HH:MM:SS"
      return date.toLocaleString(undefined, {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      });
    } catch (err) {
      console.error('Error formatting timestamp:', err);
      return 'N/A';
    }
  };

  // Function to handle direct download instead of relying on browser behavior
  const handleDownload = async (url, fileName) => {
    try {
      // Create a temporary anchor element
      const link = document.createElement('a');
      
      // Fetch the file as a blob to force download
      const response = await fetch(url);
      const blob = await response.blob();
      
      // Create a blob URL and set it as the href
      const blobUrl = window.URL.createObjectURL(blob);
      link.href = blobUrl;
      
      // Set download attribute with the original filename
      link.setAttribute('download', fileName);
      
      // Append to body, click, and remove
      document.body.appendChild(link);
      link.click();
      
      // Clean up
      document.body.removeChild(link);
      window.URL.revokeObjectURL(blobUrl);
    } catch (error) {
      console.error('Download failed:', error);
      alert('Failed to download file. Please try again.');
    }
  };

  return (
    <div className="mt-8 overflow-hidden rounded-xl border border-gray-200 shadow-sm">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">File Name</th>
            <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Upload Date & Time</th>
            <th className="px-6 py-4 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {files.map(f => {
            // Check if file is malicious (no URL or malicious verdict)
            const isMalicious = f.verdict === 'malicious' || !f.url;
            
            return (
              <tr key={f.id} className="hover:bg-gray-50 transition-colors">
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm font-medium text-gray-900">{f.originalName}</div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-500">{formatTimestamp(f.timestamp)}</div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <div className="flex justify-end space-x-2">
                    {/* Only show download button for non-malicious files with URLs */}
                    {!isMalicious && f.url && (
                      <button 
                        className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                        onClick={() => handleDownload(f.url, f.originalName)}
                      >
                        Download
                      </button>
                    )}
                    
                    {/* If malicious, show blocked notice instead of download button */}
                    {isMalicious && (
                      <span className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-gray-500 cursor-not-allowed">
                        Blocked
                      </span>
                    )}
                    
                    {showDeleteButton && onDelete && (
                      <button 
                        onClick={() => onDelete(f.id)}
                        className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
  