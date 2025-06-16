import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { SignedIn, SignedOut, UserButton, RedirectToSignIn, SignIn, SignUp } from '@clerk/clerk-react';
import UploadPage from './pages/UploadPage';
import MyFilesPage from './pages/MyFilesPage';

// Protected layout with navigation
const ProtectedLayout = ({ children }) => {
  return (
    <>
      <nav className="flex gap-6 p-4 bg-slate-800 text-white">
        <div className="flex-1">
          <a href="/upload" className="hover:underline mr-4">Upload</a>
          <a href="/my" className="hover:underline mr-4">My Files</a>
        </div>
        <div>
          <UserButton afterSignOutUrl="/sign-in" />
        </div>
      </nav>
      {children}
    </>
  );
};

// Protected route component
const ProtectedRoute = ({ children }) => {
  return (
    <>
      <SignedIn>
        <ProtectedLayout>{children}</ProtectedLayout>
      </SignedIn>
      <SignedOut>
        <RedirectToSignIn />
      </SignedOut>
    </>
  );
};

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Landing redirect - sends users to sign-in if not authenticated */}
        <Route path="/" element={
          <>
            <SignedIn>
              <Navigate to="/upload" replace />
            </SignedIn>
            <SignedOut>
              <Navigate to="/sign-in" replace />
            </SignedOut>
          </>
        } />
        
        {/* Protected routes */}
        <Route path="/upload" element={
          <ProtectedRoute>
            <UploadPage />
          </ProtectedRoute>
        } />
        
        <Route path="/my" element={
          <ProtectedRoute>
            <MyFilesPage />
          </ProtectedRoute>
        } />
        
        {/* Auth routes - using Clerk components */}
        <Route 
          path="/sign-in/*" 
          element={
            <div className="flex justify-center items-center min-h-screen bg-gray-50">
              <SignIn routing="path" path="/sign-in" fallbackRedirectUrl="/upload" />
            </div>
          } 
        />
        <Route 
          path="/sign-up/*" 
          element={
            <div className="flex justify-center items-center min-h-screen bg-gray-50">
              <SignUp routing="path" path="/sign-up" fallbackRedirectUrl="/upload" />
            </div>
          } 
        />
      </Routes>
    </BrowserRouter>
  );
}
