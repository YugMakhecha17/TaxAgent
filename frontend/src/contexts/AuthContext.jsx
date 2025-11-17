import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

const AuthContext = createContext(null);

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Initialize from localStorage on mount
  useEffect(() => {
    const initAuth = async () => {
      try {
        const storedToken = localStorage.getItem('access_token');
        if (storedToken) {
          setToken(storedToken);
          try {
            const response = await fetch(`${API_URL}/auth/me`, {
              headers: {
                'Authorization': `Bearer ${storedToken}`,
                'Content-Type': 'application/json',
              },
            });

            if (response.ok) {
              const userData = await response.json();
              setUser(userData);
              setIsAuthenticated(true);
            } else {
              // Token is invalid, clear storage
              localStorage.removeItem('access_token');
              localStorage.removeItem('user');
              setToken(null);
              setUser(null);
              setIsAuthenticated(false);
            }
          } catch (error) {
            console.error('Auth initialization error:', error);
            // If backend is not available, don't block the app
            // Just clear invalid token and continue
            localStorage.removeItem('access_token');
            localStorage.removeItem('user');
            setToken(null);
            setUser(null);
            setIsAuthenticated(false);
          }
        } else {
          setIsAuthenticated(false);
        }
      } catch (error) {
        console.error('Unexpected auth error:', error);
        setIsAuthenticated(false);
      } finally {
        setLoading(false);
      }
    };

    initAuth();
  }, []);

  // Register with email/password
  const register = useCallback(async (name, email, password) => {
    try {
      const response = await fetch(`${API_URL}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: data.detail || 'Registration failed',
        };
      }

      // Store token and user
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('user', JSON.stringify(data.user));
      setToken(data.access_token);
      setUser(data.user);
      setIsAuthenticated(true);

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.message || 'Registration error',
      };
    }
  }, []);

  // Login with email/password
  const login = useCallback(async (email, password) => {
    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: data.detail || 'Login failed',
        };
      }

      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('user', JSON.stringify(data.user));
      setToken(data.access_token);
      setUser(data.user);
      setIsAuthenticated(true);

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.message || 'Login error',
      };
    }
  }, []);

  // Google login with ID token (client-side)
  const googleLogin = useCallback(async (tokenResponse) => {
    try {
      // Send ID token to backend
      const response = await fetch(`${API_URL}/auth/google`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token: tokenResponse.id_token || tokenResponse.access_token,
          token_type: tokenResponse.id_token ? 'id_token' : 'access_token',
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: data.detail || 'Google authentication failed',
        };
      }

      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('user', JSON.stringify(data.user));
      setToken(data.access_token);
      setUser(data.user);
      setIsAuthenticated(true);

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.message || 'Google authentication error',
      };
    }
  }, []);

  // Google callback (server-side code exchange)
  const googleCallback = useCallback(async (code) => {
    try {
      const response = await fetch(`${API_URL}/auth/google/callback`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code }),
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: data.detail || 'Authentication failed',
        };
      }

      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('user', JSON.stringify(data.user));
      setToken(data.access_token);
      setUser(data.user);
      setIsAuthenticated(true);

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.message || 'Authentication error',
      };
    }
  }, []);

  // Logout
  const logout = useCallback(() => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    setToken(null);
    setUser(null);
    setIsAuthenticated(false);
  }, []);

  const value = {
    user,
    token,
    loading,
    isAuthenticated,
    register,
    login,
    googleLogin,
    googleCallback,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};