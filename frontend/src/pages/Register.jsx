import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useGoogleLogin } from '@react-oauth/google';
import { useAuth } from '../contexts/AuthContext';

const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID;

const Register = () => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [agreedToTerms, setAgreedToTerms] = useState(false);
  const { register, googleLogin } = useAuth();
  const navigate = useNavigate();

  const validateForm = () => {
    if (!name.trim()) {
      setError('Please enter your full name');
      return false;
    }

    if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
      setError('Please enter a valid email address');
      return false;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters');
      return false;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return false;
    }

    if (!agreedToTerms) {
      setError('Please agree to the Terms of Service');
      return false;
    }

    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!validateForm()) {
      return;
    }

    setLoading(true);
    const result = await register(name, email, password);
    setLoading(false);

    if (result.success) {
      setSuccess('Account created successfully! Redirecting...');
      setTimeout(() => navigate('/dashboard'), 1500);
    } else {
      setError(result.error);
    }
  };

  // Initialize Google login hook (will work if GoogleOAuthProvider is available)
  // Uses authorization code flow with PKCE by default, returns access_token
  const googleLoginHook = useGoogleLogin({
    onSuccess: async (tokenResponse) => {
      setGoogleLoading(true);
      setError('');
      setSuccess('');

      try {
        const result = await googleLogin(tokenResponse);

        if (result.success) {
          setSuccess('Google signup successful! Redirecting...');
          setTimeout(() => navigate('/dashboard'), 1500);
        } else {
          setError(result.error);
        }
      } catch (err) {
        setError('Google signup failed. Please try again.');
        console.error('Google signup error:', err);
      } finally {
        setGoogleLoading(false);
      }
    },
    onError: () => {
      setGoogleLoading(false);
      setError('Google signup was cancelled or failed.');
    },
  });

  const handleGoogleSignup = () => {
    if (!GOOGLE_CLIENT_ID) {
      setError('Google OAuth is not configured. Please use email/password registration.');
      return;
    }
    try {
      googleLoginHook();
    } catch (err) {
      setError('Google OAuth is not available. Please use email/password registration.');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-dark-grey via-light-grey to-dark-grey flex items-center justify-center p-4 py-8">
      <div className="w-full max-w-md">
        <div className="bg-light-grey rounded-2xl shadow-2xl p-8 border border-border-grey fade-in">
          {/* Header */}
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-white mb-2">Tax Intelligence</h1>
            <p className="text-text-grey">Create your account</p>
          </div>

          {/* Error Alert */}
          {error && (
            <div className="mb-4 p-4 bg-red-900/30 border border-red-700 rounded-lg text-red-300 text-sm animate-pulse">
              <div className="flex items-start gap-2">
                <span className="text-red-400 font-bold">⚠</span>
                <span>{error}</span>
              </div>
            </div>
          )}

          {/* Success Alert */}
          {success && (
            <div className="mb-4 p-4 bg-green-900/30 border border-green-700 rounded-lg text-green-300 text-sm">
              <div className="flex items-start gap-2">
                <span className="text-green-400 font-bold">✓</span>
                <span>{success}</span>
              </div>
            </div>
          )}

          {/* Email/Password Form */}
          <form onSubmit={handleSubmit} className="space-y-4 mb-6">
            {/* Name Field */}
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-text-grey mb-2">
                Full Name
              </label>
              <input
                id="name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                disabled={loading || googleLoading}
                className="w-full px-4 py-3 bg-accent-grey border border-border-grey rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-white focus:border-transparent transition disabled:opacity-50 disabled:cursor-not-allowed"
                placeholder="John Doe"
              />
            </div>

            {/* Email Field */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-text-grey mb-2">
                Email Address
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={loading || googleLoading}
                className="w-full px-4 py-3 bg-accent-grey border border-border-grey rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-white focus:border-transparent transition disabled:opacity-50 disabled:cursor-not-allowed"
                placeholder="you@example.com"
              />
            </div>

            {/* Password Field */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-text-grey mb-2">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={6}
                disabled={loading || googleLoading}
                className="w-full px-4 py-3 bg-accent-grey border border-border-grey rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-white focus:border-transparent transition disabled:opacity-50 disabled:cursor-not-allowed"
                placeholder="••••••••"
              />
              <p className="mt-1 text-xs text-text-grey">Minimum 6 characters</p>
            </div>

            {/* Confirm Password Field */}
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-text-grey mb-2">
                Confirm Password
              </label>
              <input
                id="confirmPassword"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                minLength={6}
                disabled={loading || googleLoading}
                className="w-full px-4 py-3 bg-accent-grey border border-border-grey rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-white focus:border-transparent transition disabled:opacity-50 disabled:cursor-not-allowed"
                placeholder="••••••••"
              />
            </div>

            {/* Terms Agreement */}
            <div className="flex items-start gap-2 pt-2">
              <input
                id="terms"
                type="checkbox"
                checked={agreedToTerms}
                onChange={(e) => setAgreedToTerms(e.target.checked)}
                disabled={loading || googleLoading}
                className="mt-1 w-4 h-4 rounded border-border-grey bg-accent-grey cursor-pointer"
              />
              <label htmlFor="terms" className="text-xs text-text-grey">
                I agree to the{' '}
                <a href="#" className="text-white hover:underline">
                  Terms of Service
                </a>{' '}
                and{' '}
                <a href="#" className="text-white hover:underline">
                  Privacy Policy
                </a>
              </label>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading || googleLoading}
              className="w-full bg-white text-dark-grey py-3 rounded-lg font-semibold hover:bg-gray-100 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 mt-4"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-dark-grey border-t-transparent rounded-full animate-spin"></div>
                  Creating account...
                </>
              ) : (
                'Create Account'
              )}
            </button>
          </form>

          {/* Google OAuth Section */}
          <div className="mt-6">
            {/* Divider */}
            <div className="relative mb-6">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-border-grey"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-3 bg-light-grey text-text-grey">Or sign up with</span>
              </div>
            </div>

            {/* Google OAuth Button */}
            <button
              onClick={handleGoogleSignup}
              disabled={!GOOGLE_CLIENT_ID || googleLoading || loading}
              className="w-full flex items-center justify-center gap-3 px-4 py-3 bg-accent-grey border border-border-grey rounded-lg text-white hover:bg-opacity-80 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
            >
              {googleLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  Signing up...
                </>
              ) : (
                <>
                  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                  </svg>
                  Sign up with Google
                </>
              )}
            </button>
            {!GOOGLE_CLIENT_ID && (
              <p className="mt-2 text-xs text-yellow-400/70 text-center">
                ℹ️ Configure VITE_GOOGLE_CLIENT_ID in .env to enable Google signup
              </p>
            )}
          </div>

          {/* Footer */}
          <p className="mt-8 text-center text-sm text-text-grey">
            Already have an account?{' '}
            <Link to="/login" className="text-white font-semibold hover:underline transition">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;