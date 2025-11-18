import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { sessionAPI, queryAPI, fileAPI } from '../services/api';
import ReactMarkdown from 'react-markdown';
import Squares from '../components/Squares';

const Dashboard = () => {
  const { user, logout } = useAuth();
  const [sessions, setSessions] = useState([]);
  const [currentSessionId, setCurrentSessionId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingSession, setLoadingSession] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [uploadingFile, setUploadingFile] = useState(false);
  const [showFilePanel, setShowFilePanel] = useState(false);
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);

  useEffect(() => {
    initializeDashboard();
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    if (currentSessionId) {
      loadSessionFiles();
    }
  }, [currentSessionId]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const initializeDashboard = async () => {
    try {
      // Load all sessions
      await loadSessions();
      setLoadingSession(false);
    } catch (error) {
      console.error('Failed to initialize dashboard:', error);
      setLoadingSession(false);
    }
  };

  const loadSessions = async () => {
    try {
      const response = await sessionAPI.getSessions();
      setSessions(response.data.sessions || []);
      
      // If there are existing sessions, load the most recent one
      if (response.data.sessions && response.data.sessions.length > 0) {
        await loadSession(response.data.sessions[0].session_id);
      }
    } catch (error) {
      console.error('Failed to load sessions:', error);
    }
  };

  const loadSession = async (sessionId) => {
    try {
      const response = await sessionAPI.getSession(sessionId);
      setCurrentSessionId(sessionId);
      setMessages(response.data.messages || []);
    } catch (error) {
      console.error('Failed to load session:', error);
    }
  };

  const loadSessionFiles = async () => {
    if (!currentSessionId) return;
    
    try {
      const response = await fileAPI.getSessionFiles(currentSessionId);
      setUploadedFiles(response.data.files || []);
    } catch (error) {
      console.error('Failed to load files:', error);
    }
  };

  const createNewChat = async () => {
    try {
      const response = await sessionAPI.createSession();
      const newSession = response.data;
      
      setSessions(prev => [newSession, ...prev]);
      setCurrentSessionId(newSession.session_id);
      setMessages([]);
      setUploadedFiles([]);
    } catch (error) {
      console.error('Failed to create new chat:', error);
    }
  };

  const deleteSession = async (sessionId, e) => {
    e.stopPropagation();
    
    if (!window.confirm('Are you sure you want to delete this chat?')) return;
    
    try {
      await sessionAPI.deleteSession(sessionId);
      setSessions(prev => prev.filter(s => s.session_id !== sessionId));
      
      if (currentSessionId === sessionId) {
        // Load another session or create new one
        if (sessions.length > 1) {
          const nextSession = sessions.find(s => s.session_id !== sessionId);
          await loadSession(nextSession.session_id);
        } else {
          await createNewChat();
        }
      }
    } catch (error) {
      console.error('Failed to delete session:', error);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file || !currentSessionId) return;

    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      alert('File size must be less than 10MB');
      return;
    }

    const allowedTypes = ['.pdf', '.txt', '.docx'];
    const fileExt = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (!allowedTypes.includes(fileExt)) {
      alert(`File type not allowed. Allowed types: ${allowedTypes.join(', ')}`);
      return;
    }

    setUploadingFile(true);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fileAPI.uploadFile(currentSessionId, formData);
      
      setUploadedFiles(prev => [response.data, ...prev]);
      
      // Add system message about file upload
      setMessages(prev => [
        ...prev,
        {
          role: 'system',
          content: `📎 Uploaded: ${response.data.filename} - ${response.data.summary || 'File uploaded successfully'}`,
        },
      ]);
      
      alert('File uploaded successfully!');
    } catch (error) {
      console.error('File upload failed:', error);
      alert('Failed to upload file. Please try again.');
    } finally {
      setUploadingFile(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!input.trim() || loading || !currentSessionId) return;

    const userMessage = input.trim();
    setInput('');
    setMessages((prev) => [...prev, { role: 'user', content: userMessage }]);
    setLoading(true);

    try {
      const response = await queryAPI.processQuery(currentSessionId, userMessage);
      const assistantMessage = response.data.final_response;
      
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: assistantMessage },
      ]);

      // Reload sessions to update title if it's the first message
      if (messages.length === 0) {
        await loadSessions();
      }
    } catch (error) {
      console.error('Query failed:', error);
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: 'Sorry, I encountered an error. Please try again.',
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays}d ago`;
    
    return date.toLocaleDateString();
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  };

  if (loadingSession) {
    return (
      <div className="min-h-screen bg-dark-grey flex items-center justify-center">
        <div className="text-white text-xl">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex relative overflow-hidden">
      {/* Animated Squares Background */}
      <div className="absolute inset-0 z-0">
        <Squares
          direction="diagonal"
          speed={0.5}
          borderColor="#444"
          squareSize={40}
          hoverFillColor="#222"
        />
      </div>

      {/* Dark overlay */}
      <div className="absolute inset-0 bg-dark-grey bg-opacity-90 z-[1]"></div>

      {/* Sidebar */}
      <div
        className={`relative z-[2] ${
          sidebarOpen ? 'w-80' : 'w-0'
        } transition-all duration-300 bg-light-grey border-r border-border-grey flex flex-col overflow-hidden`}
      >
        {/* Sidebar Header */}
        <div className="p-4 border-b border-border-grey">
          <button
            onClick={createNewChat}
            className="w-full px-4 py-3 bg-white text-dark-grey rounded-lg font-semibold hover:bg-gray-100 transition duration-200 flex items-center justify-center gap-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            New Chat
          </button>
        </div>

        {/* Chat History */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          <h3 className="text-xs font-semibold text-text-grey uppercase tracking-wider mb-2">
            Recent Chats
          </h3>
          {sessions.map((session) => (
            <div
              key={session.session_id}
              onClick={() => loadSession(session.session_id)}
              className={`group p-3 rounded-lg cursor-pointer transition duration-200 ${
                currentSessionId === session.session_id
                  ? 'bg-accent-grey text-white'
                  : 'hover:bg-accent-grey hover:bg-opacity-50 text-text-grey hover:text-white'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">
                    {session.title || 'New Chat'}
                  </p>
                  <p className="text-xs text-text-grey mt-1">
                    {formatTimestamp(session.last_query_time)}
                  </p>
                </div>
                <button
                  onClick={(e) => deleteSession(session.session_id, e)}
                  className="opacity-0 group-hover:opacity-100 p-1 hover:bg-red-500 hover:bg-opacity-20 rounded transition"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* User Profile in Sidebar */}
        <div className="p-4 border-t border-border-grey">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-white rounded-full flex items-center justify-center text-dark-grey font-bold">
                {user?.name?.charAt(0).toUpperCase()}
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-white truncate">{user?.name}</p>
                <p className="text-xs text-text-grey truncate">{user?.email}</p>
              </div>
            </div>
            <button
              onClick={logout}
              className="p-2 hover:bg-accent-grey rounded-lg transition"
              title="Logout"
            >
              <svg className="w-5 h-5 text-text-grey" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="relative z-[2] flex-1 flex flex-col">
        {/* Header */}
        <header className="bg-light-grey bg-opacity-80 backdrop-blur-sm border-b border-border-grey px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="p-2 hover:bg-accent-grey rounded-lg transition"
              >
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
              <div>
                <h1 className="text-xl font-bold text-white">Tax Intelligence</h1>
                <p className="text-xs text-text-grey">AI-Powered GST & Tax Assistant</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {/* File Upload Button */}
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileUpload}
                accept=".pdf,.txt,.docx"
                className="hidden"
                disabled={!currentSessionId || uploadingFile}
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={!currentSessionId || uploadingFile}
                className="px-4 py-2 bg-accent-grey hover:bg-opacity-80 text-white rounded-lg transition duration-200 flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                title="Upload tax document"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
                {uploadingFile ? 'Uploading...' : 'Upload'}
              </button>

              {/* Files Panel Toggle */}
              {uploadedFiles.length > 0 && (
                <button
                  onClick={() => setShowFilePanel(!showFilePanel)}
                  className="px-4 py-2 bg-accent-grey hover:bg-opacity-80 text-white rounded-lg transition duration-200 flex items-center gap-2"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Files ({uploadedFiles.length})
                </button>
              )}
            </div>
          </div>
        </header>

        {/* Chat Container */}
        <div className="flex-1 flex overflow-hidden">
          {/* Messages Area */}
          <div className="flex-1 flex flex-col px-4 py-6">
            <div className="flex-1 overflow-y-auto mb-6 space-y-4 max-w-4xl mx-auto w-full">
              {messages.length === 0 && !currentSessionId ? (
                <div className="flex items-center justify-center h-full">
                  <div className="text-center max-w-2xl">
                    <div className="mb-6">
                      <div className="inline-block p-4 bg-light-grey rounded-full mb-4">
                        <svg className="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                      </div>
                    </div>
                    <h2 className="text-3xl font-bold text-white mb-4">
                      Welcome to Tax Intelligence
                    </h2>
                    <p className="text-text-grey text-lg mb-6">
                      Create a new chat to get started or select an existing conversation.
                    </p>
                    <button
                      onClick={createNewChat}
                      className="px-6 py-3 bg-white text-dark-grey rounded-lg font-semibold hover:bg-gray-100 transition duration-200"
                    >
                      Start New Chat
                    </button>
                  </div>
                </div>
              ) : messages.length === 0 ? (
                <div className="flex items-center justify-center h-full">
                  <div className="text-center max-w-2xl">
                    <h2 className="text-2xl font-bold text-white mb-4">Start a Conversation</h2>
                    <p className="text-text-grey text-lg mb-6">
                      Ask me anything about GST, taxation, legal clarifications, or recent updates.
                    </p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-left">
                      <div className="p-4 bg-light-grey rounded-lg border border-border-grey">
                        <h3 className="text-white font-semibold mb-2">📊 Dynamic Updates</h3>
                        <p className="text-text-grey text-sm">Latest GST rates, circulars, and policy changes</p>
                      </div>
                      <div className="p-4 bg-light-grey rounded-lg border border-border-grey">
                        <h3 className="text-white font-semibold mb-2">⚖️ Legal Reference</h3>
                        <p className="text-text-grey text-sm">CGST/SGST/IGST Act sections and provisions</p>
                      </div>
                      <div className="p-4 bg-light-grey rounded-lg border border-border-grey">
                        <h3 className="text-white font-semibold mb-2">🔍 Analysis</h3>
                        <p className="text-text-grey text-sm">Explanations and interpretations</p>
                      </div>
                      <div className="p-4 bg-light-grey rounded-lg border border-border-grey">
                        <h3 className="text-white font-semibold mb-2">💰 Tax Knowledge</h3>
                        <p className="text-text-grey text-sm">Income tax, deductions, and compliance</p>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                messages.map((message, index) => (
                  <div
                    key={index}
                    className={`flex ${
                      message.role === 'user' ? 'justify-end' : 
                      message.role === 'system' ? 'justify-center' : 'justify-start'
                    }`}
                  >
                    <div
                      className={`max-w-3xl rounded-2xl px-6 py-4 ${
                        message.role === 'user'
                          ? 'bg-white text-dark-grey'
                          : message.role === 'system'
                          ? 'bg-blue-500 bg-opacity-20 text-blue-300 border border-blue-500 border-opacity-30 text-sm'
                          : 'bg-light-grey text-white border border-border-grey'
                      }`}
                    >
                      {message.role === 'assistant' ? (
                        <div className="prose prose-invert max-w-none">
                          <ReactMarkdown className="text-white">{message.content}</ReactMarkdown>
                        </div>
                      ) : (
                        <p className="whitespace-pre-wrap">{message.content}</p>
                      )}
                    </div>
                  </div>
                ))
              )}
              {loading && (
                <div className="flex justify-start">
                  <div className="bg-light-grey border border-border-grey rounded-2xl px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-white rounded-full animate-bounce"></div>
                      <div className="w-2 h-2 bg-white rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                      <div className="w-2 h-2 bg-white rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
                    </div>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Input Area */}
            {currentSessionId && (
              <form onSubmit={handleSubmit} className="flex gap-4 max-w-4xl mx-auto w-full">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Ask about GST, taxation, legal clarifications, or upload documents..."
                  className="flex-1 px-6 py-4 bg-light-grey border border-border-grey rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-white focus:border-transparent transition"
                  disabled={loading}
                />
                <button
                  type="submit"
                  disabled={loading || !input.trim()}
                  className="px-8 py-4 bg-white text-dark-grey rounded-xl font-semibold hover:bg-gray-100 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  <span>Send</span>
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                  </svg>
                </button>
              </form>
            )}
          </div>

          {/* Files Panel */}
          {showFilePanel && uploadedFiles.length > 0 && (
            <div className="w-80 bg-light-grey border-l border-border-grey p-4 overflow-y-auto">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-white font-semibold">Uploaded Files</h3>
                <button
                  onClick={() => setShowFilePanel(false)}
                  className="p-1 hover:bg-accent-grey rounded transition"
                >
                  <svg className="w-5 h-5 text-text-grey" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              <div className="space-y-3">
                {uploadedFiles.map((file) => (
                  <div
                    key={file.file_id}
                    className="p-3 bg-accent-grey rounded-lg border border-border-grey"
                  >
                    <div className="flex items-start gap-2 mb-2">
                      <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-white truncate">{file.filename}</p>
                        <p className="text-xs text-text-grey mt-1">
                          {formatFileSize(file.file_size)} • {formatTimestamp(file.upload_timestamp)}
                        </p>
                      </div>
                    </div>
                    {file.summary && (
                      <p className="text-xs text-text-grey line-clamp-3">{file.summary}</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;