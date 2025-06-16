# FileScan Project

FileScan is a secure file management system that allows users to upload, scan, and manage their files safely. The system scans files for malware and viruses before storing them, and organizes files per user with a secure authentication system.

## Features

- **Secure Authentication**: User authentication with Clerk
- **File Scanning**: Automatic virus and malware scanning of uploaded files
- **User-Specific Storage**: Each user can only see and manage their own files
- **Clean/Malicious Classification**: Clear separation between safe and potentially malicious files
- **Responsive UI**: Modern and easy to use interface

## Project Structure

```
fileScanProject/
├── frontend/            # React frontend application
│   ├── src/
│   │   ├── components/  # Reusable UI components
│   │   ├── pages/       # Page components
│   │   ├── utils/       # Utility functions and services
│   │   ├── App.jsx      # Main app component with routing
│   │   └── main.jsx     # Entry point with providers
│   ├── public/          # Static assets
│   └── .env             # Frontend environment variables
│
├── backend/             # Express backend API
│   ├── controllers/     # API route controllers
│   ├── routes/          # API route definitions
│   ├── utils/           # Utility functions and middleware
│   ├── server.js        # Main server entry point
│   └── .env             # Backend environment variables
│
└── README.md            # This file
```

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- [Clerk](https://clerk.com/) account for authentication
- [Cloudinary](https://cloudinary.com/) account for file storage
- [VirusTotal](https://www.virustotal.com/) API key for virus scanning

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/fileScanProject.git
cd fileScanProject
```

### 2. Set up the Backend

```bash
cd backend
npm install
```

### 3. Set up the Frontend

```bash
cd frontend
npm install
```

## Environment Variables

### Backend (.env)

Create a `.env` file in the `backend` directory with the following variables:

```
PORT=3001
VT_API_KEY=your_virustotal_api_key
CLOUDINARY_CLOUD_NAME=your_cloudinary_cloud_name
CLOUDINARY_API_KEY=your_cloudinary_api_key
CLOUDINARY_API_SECRET=your_cloudinary_api_secret
CLERK_SECRET_KEY=your_clerk_secret_key
```

- `PORT`: The port on which the backend server will run
- `VT_API_KEY`: API key for VirusTotal scanning service
- `CLOUDINARY_*`: Credentials for your Cloudinary account
- `CLERK_SECRET_KEY`: Secret key from your Clerk dashboard

### Frontend (.env)

Create a `.env` file in the `frontend` directory with the following variables:

```
VITE_API_URL=http://localhost:3001/api
VITE_CLERK_PUBLISHABLE_KEY=your_clerk_publishable_key
VITE_CLERK_SIGN_IN_URL=/sign-in
VITE_CLERK_SIGN_UP_URL=/sign-up
```

- `VITE_API_URL`: URL of your backend API
- `VITE_CLERK_PUBLISHABLE_KEY`: Publishable key from your Clerk dashboard
- Other Clerk configuration values (default values are provided)

## Running The Application

### Start the Backend

```bash
cd backend
npm run dev
```

The backend server will start on port 3001 (or the port specified in your .env file).

### Start the Frontend

```bash
cd frontend
npm run dev
```

The frontend development server will start, and you can access the application at `http://localhost:5173`.

## Authentication Flow

The application uses Clerk for authentication. The authentication flow works as follows:

1. New users land on the sign-in page
2. They can either sign in with existing credentials or sign up for a new account
3. After authentication, they are redirected to the upload page
4. All routes except authentication routes are protected and require login
5. Each user can only see and manage their own files

## File Handling

### Upload Process

1. Files are uploaded from the frontend to the backend
2. The backend scans the file for viruses using VirusTotal API
3. The scanning result determines if the file is safe or potentially malicious
4. Safe files are stored in Cloudinary with user ID tags
5. Malicious files are flagged and not stored

### File Management

- The "Upload" page allows users to upload new files and see recent uploads
- The "My Files" page shows all safe files that belong to the user
- Users can delete individual files or all files
- File listings are protected and user-specific

## API Endpoints

### Files

- `POST /api/files` - Upload a new file
- `GET /api/files` - Get all files for the authenticated user
- `DELETE /api/files/:fileId` - Delete a specific file
- `DELETE /api/files` - Delete all files for the authenticated user

## Security Features

1. **Authentication**: Users must be authenticated to access most routes
2. **User Isolation**: Users can only see and manage their own files
3. **File Scanning**: Files are scanned for malware before storage
4. **Token Verification**: API requests require valid authentication tokens
5. **User-Specific LocalStorage**: Client-side storage is separated by user ID

## Troubleshooting

### Common Issues

1. **Authentication Errors**

   - Verify that your Clerk keys are correct
   - Check browser console for specific error messages

2. **File Upload Issues**

   - Ensure the file size is within limits (10MB)
   - Check that the file type is allowed

3. **API Connection Issues**
   - Verify that the backend server is running
   - Check that CORS is properly configured

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Clerk](https://clerk.com/) for authentication
- [Cloudinary](https://cloudinary.com/) for file storage
- [VirusTotal](https://www.virustotal.com/) for file scanning
