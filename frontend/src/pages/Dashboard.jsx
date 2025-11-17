import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { sessionAPI, queryAPI } from '../services/api';
import ReactMarkdown from 'react-markdown';
import Squares from '../components/Squares'; // Import the Squares component

const Dashboard = () => {
  const { user, logout } = useAuth();
  const [sessionId, setSessionId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingSession, setLoadingSession] = useState(true);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    initializeSession();
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const initializeSession = async () => {
    try {
      const response = await sessionAPI.createSession();
      setSessionId(response.data.session_id);
      setLoadingSession(false);
    } catch (error) {
      console.error('Failed to create session:', error);
      setLoadingSession(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!input.trim() || loading || !sessionId) return;

    const userMessage = input.trim();
    setInput('');
    setMessages((prev) => [...prev, { role: 'user', content: userMessage }]);
    setLoading(true);

    try {
      const response = await queryAPI.processQuery(sessionId, userMessage);
      const assistantMessage = response.data.final_response;
      
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: assistantMessage },
      ]);
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

  if (loadingSession) {
    return (
      <div className="min-h-screen bg-dark-grey flex items-center justify-center">
        <div className="text-white text-xl">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col relative overflow-hidden">
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

      {/* Dark overlay for better text readability */}
      <div className="absolute inset-0 bg-dark-grey bg-opacity-90 z-[1]"></div>

      {/* Content Container */}
      <div className="relative z-[2] flex flex-col min-h-screen">
        {/* Header */}
        <header className="bg-light-grey bg-opacity-80 backdrop-blur-sm border-b border-border-grey px-6 py-4">
          <div className="max-w-7xl mx-auto flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white">Tax Intelligence</h1>
              <p className="text-sm text-text-grey">AI-Powered GST & Tax Assistant</p>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <p className="text-white font-medium">{user?.name}</p>
                <p className="text-xs text-text-grey">{user?.email}</p>
              </div>
              <button
                onClick={logout}
                className="px-4 py-2 bg-accent-grey hover:bg-opacity-80 text-white rounded-lg transition duration-200"
              >
                Logout
              </button>
            </div>
          </div>
        </header>

        {/* Chat Container */}
        <div className="flex-1 flex flex-col max-w-7xl mx-auto w-full px-4 py-6">
          {/* Messages Area */}
          <div className="flex-1 overflow-y-auto mb-6 space-y-4">
            {messages.length === 0 ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center max-w-2xl">
                  <div className="mb-6">
                    <div className="inline-block p-4 bg-light-grey rounded-full mb-4">
                      <svg
                        className="w-12 h-12 text-white"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                        />
                      </svg>
                    </div>
                  </div>
                  <h2 className="text-3xl font-bold text-white mb-4">
                    Welcome to Tax Intelligence
                  </h2>
                  <p className="text-text-grey text-lg mb-6">
                    Ask me anything about GST, taxation, legal clarifications, or recent updates.
                  </p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-left">
                    <div className="p-4 bg-light-grey rounded-lg border border-border-grey">
                      <h3 className="text-white font-semibold mb-2">📊 Dynamic Updates</h3>
                      <p className="text-text-grey text-sm">
                        Latest GST rates, circulars, and policy changes
                      </p>
                    </div>
                    <div className="p-4 bg-light-grey rounded-lg border border-border-grey">
                      <h3 className="text-white font-semibold mb-2">⚖️ Legal Reference</h3>
                      <p className="text-text-grey text-sm">
                        CGST/SGST/IGST Act sections and provisions
                      </p>
                    </div>
                    <div className="p-4 bg-light-grey rounded-lg border border-border-grey">
                      <h3 className="text-white font-semibold mb-2">🔍 Analysis</h3>
                      <p className="text-text-grey text-sm">
                        Explanations and interpretations
                      </p>
                    </div>
                    <div className="p-4 bg-light-grey rounded-lg border border-border-grey">
                      <h3 className="text-white font-semibold mb-2">💰 Tax Knowledge</h3>
                      <p className="text-text-grey text-sm">
                        Income tax, deductions, and compliance
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              messages.map((message, index) => (
                <div
                  key={index}
                  className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  <div
                    className={`max-w-3xl rounded-2xl px-6 py-4 ${
                      message.role === 'user'
                        ? 'bg-white text-dark-grey'
                        : 'bg-light-grey text-white border border-border-grey'
                    }`}
                  >
                    {message.role === 'assistant' ? (
                      <div className="prose prose-invert max-w-none">
                        <ReactMarkdown className="text-white">
                          {message.content}
                        </ReactMarkdown>
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
          <form onSubmit={handleSubmit} className="flex gap-4">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about GST, taxation, legal clarifications..."
              className="flex-1 px-6 py-4 bg-light-grey border border-border-grey rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-white focus:border-transparent transition"
              disabled={loading}
            />
            <button
              type="submit"
              disabled={loading || !input.trim()}
              className="px-8 py-4 bg-white text-dark-grey rounded-xl font-semibold hover:bg-gray-100 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              <span>Send</span>
              <svg
                className="w-5 h-5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                />
              </svg>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;