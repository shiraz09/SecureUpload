import axios from 'axios';
import crypto from 'crypto';
import FormData from 'form-data';

const VT = 'https://www.virustotal.com/api/v3';
const POLLING_INTERVAL_MS = 8000; // 8 seconds between polling requests (max 4 req/min for free tier)
const MAX_RETRIES = 3;

/**
 * Scan a file using VirusTotal API
 * @param {Buffer} buffer - File buffer
 * @param {string} filename - Original filename
 * @param {string} key - VirusTotal API key
 * @returns {Promise<string>}
 */
export async function scanFile(buffer, filename, key) {
  try {
    // Calculate SHA-256 hash of file first
    const hash = crypto.createHash('sha256').update(buffer).digest('hex');
    console.log(`File hash: ${hash}`);
    
    // Try to get the file by hash first (to avoid unnecessary uploads)
    try {
      console.log('Checking if file already exists in VirusTotal by hash...');
      const response = await axios.get(`${VT}/files/${hash}`, { 
        headers: { 'x-apikey': key } 
      });
      
      console.log('File already exists in VirusTotal, using existing analysis');
      return hash; // Return hash as ID for later analysis
    } catch (hashError) {
      // If 404, file doesn't exist yet, so we'll upload it
      if (hashError.response && hashError.response.status === 404) {
        console.log('File not found in VirusTotal, uploading new file...');
      } else {
        // For other errors with hash lookup, log but continue to try upload
        console.warn('Error checking file by hash:', hashError.message);
        if (hashError.response && hashError.response.data) {
          console.error('Full error details:', JSON.stringify(hashError.response.data));
        }
      }
      
      // Proceed with uploading the file using proper Node.js FormData
      const form = new FormData();
      form.append('file', buffer, {
        filename,
        contentType: 'application/octet-stream'
      });
      
      const { data } = await axios.post(`${VT}/files`, form, { 
        headers: { 
          'x-apikey': key,
          ...form.getHeaders() // Important for proper multipart/form-data
        } 
      });
      
      console.log('File successfully uploaded to VirusTotal');
      
      // Return the ID from the upload response
      return data.data.id;
    }
  } catch (error) {
    // Handle specific error cases
    if (error.response) {
      // Handle rate limiting
      if (error.response.status === 429) {
        console.error('VirusTotal API rate limit exceeded:', error.response.status);
        throw new Error('RATE_LIMIT_EXCEEDED');
      }
      
      // Log the full error
      console.error('API Error:', error.response.status);
      if (error.response.data) {
        console.error('Error details:', JSON.stringify(error.response.data));
      }
    }
    
    // For other errors, just throw them
    throw error;
  }
}

/**
 * Get analysis results for a file from VirusTotal
 * @param {string} id - File ID
 * @param {string} key - VirusTotal API key
 * @returns {Promise<{attributes: {status: string, stats: {malicious: number, suspicious: number, harmless: number}}>>}
 */
export async function getAnalysis(id, key) {
  try {
    // First determine if we're dealing with a file hash or an analysis ID
    // File hashes are typically 64 character hex strings
    const isFileHash = /^[a-fA-F0-9]{64}$/.test(id);
    
    if (isFileHash) {
      // If it's a file hash, first get the file info
      console.log('Detected ID as file hash, getting file info first...');
      try {
        const fileResponse = await axios.get(`${VT}/files/${id}`, { 
          headers: { 'x-apikey': key } 
        });
        
        // If we have analysis stats directly in the file response, use those
        if (fileResponse.data.data.attributes?.last_analysis_stats) {
          console.log('Found analysis stats in file response');
          return {
            attributes: {
              status: 'completed',
              stats: fileResponse.data.data.attributes.last_analysis_stats
            }
          };
        }
        
        // If we have a last_analysis_id, use that to get the detailed analysis
        if (fileResponse.data.data.attributes?.last_analysis_id) {
          console.log('Found analysis ID in file response, fetching analysis...');
          const analysisId = fileResponse.data.data.attributes.last_analysis_id;
          
          // Now get the actual analysis with the correct ID
          const analysisResponse = await axios.get(`${VT}/analyses/${analysisId}`, { 
            headers: { 'x-apikey': key } 
          });
          
          return {
            attributes: {
              status: 'completed',
              stats: analysisResponse.data.data.attributes.stats
            }
          };
        }
        
        // If no analysis stats or ID available, analysis is pending
        console.log('No analysis results available yet');
        throw new Error('ANALYSIS_PENDING');
      } catch (fileError) {
        // Handle rate limiting
        if (fileError.response && fileError.response.status === 429) {
          console.error('Rate limit exceeded while getting file info');
          throw new Error('RATE_LIMIT_EXCEEDED');
        }
        
        // Log the detailed error
        console.error('Error getting file info from VirusTotal:', fileError.message);
        if (fileError.response && fileError.response.data) {
          console.error('Error details:', JSON.stringify(fileError.response.data));
        }
        
        // Re-throw the error
        throw fileError;
      }
    } else {
      // This is a regular analysis ID, proceed normally
      try {
        // Try to get analysis results
        const { data } = await axios.get(`${VT}/analyses/${id}`, { 
          headers: { 'x-apikey': key } 
        });
        
        // If analysis is completed, return the verdict
        if (data.data.attributes.status === 'completed') {
          return {
            attributes: {
              status: 'completed',
              stats: data.data.attributes.stats
            }
          };
        }
        
        // If analysis is still in progress, throw a special error
        throw new Error('ANALYSIS_PENDING');
      } catch (analysisError) {
        // Handle rate limiting
        if (analysisError.response && analysisError.response.status === 429) {
          console.error('Rate limit exceeded while getting analysis');
          throw new Error('RATE_LIMIT_EXCEEDED');
        }
        
        // Analysis not available yet
        if (analysisError.response && 
            analysisError.response.status === 400 && 
            analysisError.response.data?.error?.code === 'NotAvailableYet') {
          console.log('Analysis not available yet');
          throw new Error('ANALYSIS_PENDING');
        }
        
        // Log the detailed error
        console.error('Error getting analysis from VirusTotal:', analysisError.message);
        if (analysisError.response && analysisError.response.data) {
          console.error('Analysis error details:', JSON.stringify(analysisError.response.data));
        }
        
        // Re-throw the error
        throw analysisError;
      }
    }
  } catch (error) {
    // Re-throw specific error types
    if (error.message === 'RATE_LIMIT_EXCEEDED' || 
        error.message === 'ANALYSIS_PENDING') {
      throw error;
    }
    
    // For any other error, log and throw
    console.error('Unexpected error in getAnalysis:', error.message);
    throw error;
  }
}

/**
 * Wait for analysis to complete with proper polling
 * @param {string} id - File ID
 * @param {string} key - VirusTotal API key
 * @param {number} maxRetries - Maximum number of retries
 * @returns {Promise<{attributes: {status: string, stats: {malicious: number, suspicious: number, harmless: number}}>>}
 */
export async function waitForAnalysis(id, key, maxRetries = MAX_RETRIES) {
  let retries = 0;
  
  while (retries < maxRetries) {
    try {
      // Wait before polling (wait first to avoid immediate rate limit)
      if (retries > 0) {
        console.log(`Waiting ${POLLING_INTERVAL_MS/1000}s before polling VirusTotal again...`);
        await new Promise(resolve => setTimeout(resolve, POLLING_INTERVAL_MS));
      }
      
      console.log(`Polling VirusTotal for analysis results (attempt ${retries + 1}/${maxRetries})...`);
      const result = await getAnalysis(id, key);
      
      if (result.attributes.status === 'completed') {
        console.log('Analysis completed successfully');
        return result;
      }
      
      retries++;
    } catch (error) {
      if (error.message === 'RATE_LIMIT_EXCEEDED') {
        console.log('Rate limit hit, waiting longer before retry...');
        await new Promise(resolve => setTimeout(resolve, POLLING_INTERVAL_MS * 2));
        retries++;
        continue;
      }
      
      // For other errors, just throw
      throw error;
    }
  }
  
  // If we've exhausted retries, we can't determine the verdict
  console.log('Max retries reached, unable to determine file verdict');
  throw new Error('ANALYSIS_TIMEOUT');
}
