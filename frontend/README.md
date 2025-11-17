# Tax Intelligence Frontend

A modern React frontend for the Tax Intelligence GST Agent application.

## Features

- 🔐 User Authentication (Email/Password & Google OAuth)
- 💬 Real-time Chat Interface
- 🎨 Professional Dark Grey & White Theme
- 📱 Responsive Design
- 🔄 Session Management

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file in the frontend directory:
```env
VITE_API_URL=http://localhost:8000
VITE_GOOGLE_CLIENT_ID=your_google_client_id_here
```

3. Start the development server:
```bash
npm run dev
```

The frontend will be available at `http://localhost:3000`

## Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add `http://localhost:3000` to authorized JavaScript origins
6. Copy the Client ID to your `.env` file

## Build for Production

```bash
npm run build
```

The built files will be in the `dist` directory.

