# GST Agent Application

A full-stack GST (Goods and Services Tax) intelligence application with multi-agent AI capabilities. The application provides real-time GST updates, legal information, and analytical insights through three specialized AI agents.

## Features

- **User Authentication**: Secure user registration and login with JWT tokens
- **Dynamic Agent**: Handles real-time GST/economic updates and circulars
- **Static Agent**: Provides legal and static GST information
- **Analytical Agent**: Generates AI-derived summaries, FAQs, and interpretations
- **Database Integration**: SQLite database for user data, sessions, and conversation history
- **Modern UI**: Professional, responsive frontend built with React and Tailwind CSS

## Tech Stack

### Backend
- FastAPI
- SQLAlchemy (SQLite)
- JWT Authentication
- LangChain & LangGraph
- Google Gemini AI

### Frontend
- React 18
- Vite
- Tailwind CSS
- React Router
- Axios

## Setup Instructions

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm or yarn

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the backend directory:
```env
GOOGLE_API_KEY=your_google_api_key_here
SECRET_KEY=your_secret_key_here_change_in_production
```

5. Run the backend server:
```bash
python main.py
```

The backend will be available at `http://localhost:8000`

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

The frontend will be available at `http://localhost:3000`

## Database

The application uses SQLite database (`gst_agent.db`) which is automatically created when you run the backend for the first time. The database includes:

- **users**: User accounts and authentication
- **conversation_sessions**: Chat sessions
- **conversation_messages**: Individual messages in sessions
- **query_history**: History of all queries

## API Endpoints

### Authentication
- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login and get access token
- `GET /auth/me` - Get current user information

### Queries
- `POST /query` - Process a GST query (requires authentication)
- `POST /session` - Create a new conversation session
- `GET /session/{session_id}` - Get a specific session
- `GET /sessions` - Get all sessions for current user
- `DELETE /session/{session_id}` - Delete a session

## Usage

1. Start the backend server
2. Start the frontend development server
3. Open `http://localhost:3000` in your browser
4. Register a new account or login
5. Start asking GST-related questions!

## Project Structure

```
GST_Agent/
├── backend/
│   ├── main.py           # FastAPI application
│   ├── database.py       # Database models and setup
│   ├── auth.py           # Authentication utilities
│   └── requirements.txt  # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── pages/        # React pages
│   │   ├── contexts/     # React contexts
│   │   ├── services/     # API services
│   │   └── App.jsx       # Main app component
│   ├── package.json      # Node dependencies
│   └── vite.config.js    # Vite configuration
└── README.md
```

## Notes

- Make sure to set your `GOOGLE_API_KEY` in the `.env` file for the AI agents to work
- The database file will be created automatically in the backend directory
- JWT tokens expire after 30 days (configurable in `auth.py`)
- The application uses CORS middleware to allow frontend-backend communication

## License

This project is for educational/demonstration purposes.

