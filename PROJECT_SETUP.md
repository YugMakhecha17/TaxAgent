# Tax Intelligence - Full Stack Setup Guide

This guide will help you set up the complete full-stack Tax Intelligence application with authentication, Google OAuth, and database connectivity.

## Project Structure

```
GST_Agent/
├── backend/
│   ├── main.py              # FastAPI backend with authentication
│   ├── requirements.txt    # Python dependencies
│   └── tax_intelligence.db  # SQLite database (auto-created)
├── frontend/
│   ├── src/
│   │   ├── pages/          # React pages (Login, Register, Dashboard)
│   │   ├── contexts/       # React contexts (AuthContext)
│   │   ├── services/      # API services
│   │   └── App.jsx         # Main app component
│   ├── package.json        # Node dependencies
│   └── vite.config.js      # Vite configuration
└── README.md
```

## Prerequisites

- Python 3.8+
- Node.js 16+
- npm or yarn
- Google Cloud Console account (for OAuth)

## Backend Setup

### 1. Navigate to backend directory

```bash
cd backend
```

### 2. Create virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Create `.env` file

Create a `.env` file in the `backend` directory:

```env
GOOGLE_API_KEY=your_google_gemini_api_key_here
SECRET_KEY=your_secret_key_here_change_in_production
```

**Note:** Generate a secure SECRET_KEY using:
```python
import secrets
print(secrets.token_urlsafe(32))
```

### 5. Run the backend server

```bash
python main.py
```

The backend will be available at `http://localhost:8000`

## Frontend Setup

### 1. Navigate to frontend directory

```bash
cd frontend
```

### 2. Install dependencies

```bash
npm install
```

### 3. Create `.env` file

Create a `.env` file in the `frontend` directory:

```env
VITE_API_URL=http://localhost:8000
VITE_GOOGLE_CLIENT_ID=your_google_oauth_client_id_here
```

### 4. Get Google OAuth Client ID

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to "APIs & Services" > "Credentials"
4. Click "Create Credentials" > "OAuth client ID"
5. Select "Web application"
6. Add `http://localhost:3000` to "Authorized JavaScript origins"
7. Add `http://localhost:3000` to "Authorized redirect URIs"
8. Copy the Client ID to your `.env` file

### 5. Start the development server

```bash
npm run dev
```

The frontend will be available at `http://localhost:3000`

## Database

The SQLite database (`tax_intelligence.db`) is automatically created in the `backend` directory when you first run the backend server. It includes:

- **users**: User accounts and authentication
- **sessions**: Chat sessions linked to users
- **messages**: Individual messages in sessions
- **query_history**: History of all queries for analytics

## Features

### Authentication
- ✅ Email/Password registration and login
- ✅ Google OAuth sign-in
- ✅ JWT token-based authentication
- ✅ Protected routes

### Chat Interface
- ✅ Real-time tax query processing
- ✅ Multi-agent AI system (Dynamic, Static, Analytical, Tax Knowledge)
- ✅ Session management
- ✅ Markdown rendering for responses
- ✅ Professional dark grey and white theme

### API Endpoints

#### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - Login user
- `POST /auth/google` - Google OAuth authentication
- `GET /auth/me` - Get current user (requires auth)

#### Sessions
- `POST /session` - Create new session (requires auth)
- `GET /session/{session_id}` - Get session (requires auth)
- `GET /sessions` - Get all user sessions (requires auth)
- `DELETE /session/{session_id}` - Delete session

#### Queries
- `POST /session/{session_id}/query` - Process tax query (requires auth)

## Usage

1. Start the backend server (port 8000)
2. Start the frontend development server (port 3000)
3. Open `http://localhost:3000` in your browser
4. Register a new account or login with Google
5. Start asking GST and tax-related questions!

## Troubleshooting

### Backend Issues

- **Database errors**: Delete `tax_intelligence.db` and restart the server to recreate the database
- **Import errors**: Make sure all dependencies are installed: `pip install -r requirements.txt`
- **CORS errors**: Check that the frontend URL is in the CORS origins list in `main.py`

### Frontend Issues

- **API connection errors**: Verify `VITE_API_URL` in `.env` matches your backend URL
- **Google OAuth not working**: Check that your Client ID is correct and authorized origins are set
- **Build errors**: Clear `node_modules` and reinstall: `rm -rf node_modules && npm install`

## Production Deployment

### Backend
- Use a production ASGI server like Gunicorn with Uvicorn workers
- Set secure `SECRET_KEY` in environment variables
- Use a production database (PostgreSQL recommended)
- Configure proper CORS origins

### Frontend
- Build the frontend: `npm run build`
- Serve the `dist` directory with a web server (Nginx, Apache, etc.)
- Update `VITE_API_URL` to your production backend URL
- Configure HTTPS for Google OAuth

## Security Notes

- Never commit `.env` files to version control
- Use strong, randomly generated `SECRET_KEY` in production
- Implement rate limiting for API endpoints
- Use HTTPS in production
- Regularly update dependencies

## License

This project is for educational purposes.

