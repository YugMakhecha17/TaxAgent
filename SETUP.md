# Quick Setup Guide

## Backend Setup

1. **Navigate to backend directory:**
   ```bash
   cd backend
   ```

2. **Create and activate virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Mac/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create `.env` file in backend directory:**
   ```env
   GOOGLE_API_KEY=your_google_api_key_here
   SECRET_KEY=your_secret_key_here
   ```

5. **Run the backend:**
   ```bash
   python main.py
   ```
   Backend will run on `http://localhost:8000`

## Frontend Setup

1. **Navigate to frontend directory:**
   ```bash
   cd frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm run dev
   ```
   Frontend will run on `http://localhost:3000`

## First Time Usage

1. Open `http://localhost:3000` in your browser
2. Click "Sign up" to create a new account
3. Fill in the registration form
4. After registration, you'll be automatically logged in
5. You'll see a welcome message: "Welcome back, {username}!"
6. Start asking GST-related questions!

## Troubleshooting

### Backend Issues
- **Database not created**: The database is created automatically on first run. Make sure you have write permissions in the backend directory.
- **Import errors**: Make sure all dependencies are installed: `pip install -r requirements.txt`
- **API key error**: Make sure your `GOOGLE_API_KEY` is set in the `.env` file

### Frontend Issues
- **Cannot connect to backend**: Make sure the backend is running on port 8000
- **CORS errors**: The backend CORS middleware is configured to allow requests from `http://localhost:3000`
- **Build errors**: Make sure Node.js 16+ is installed and run `npm install`

### Authentication Issues
- **Login fails**: Check that the username and password are correct
- **Token expired**: Tokens expire after 30 days. Simply log in again.
- **401 errors**: Make sure you're logged in and the token is valid

## Database

The SQLite database (`gst_agent.db`) is automatically created in the backend directory when you first run the application. It includes:
- User accounts
- Conversation sessions
- Message history
- Query history

## API Documentation

Once the backend is running, you can access the API documentation at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

