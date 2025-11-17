import streamlit as st
import requests
import json
import uuid
from datetime import datetime
import time

# Configure the page
st.set_page_config(
    page_title="GST Intelligence Chatbot",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
def load_css():
    st.markdown("""
    <style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        font-weight: bold;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #2e86ab;
        margin-bottom: 1rem;
    }
    .chat-container {
        background-color: #f8f9fa;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
        border-left: 5px solid #1f77b4;
    }
    .user-message {
        background-color: #e3f2fd;
        padding: 15px;
        border-radius: 15px;
        margin: 10px 0;
        border: 1px solid #bbdefb;
    }
    .assistant-message {
        background-color: #ffffff;
        padding: 15px;
        border-radius: 15px;
        margin: 10px 0;
        border: 1px solid #e0e0e0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .agent-badge {
        background-color: #ff6b6b;
        color: white;
        padding: 4px 8px;
        border-radius: 12px;
        font-size: 0.8rem;
        margin-left: 10px;
    }
    .timestamp {
        font-size: 0.8rem;
        color: #666;
        text-align: right;
    }
    .stButton button {
        background-color: #1f77b4;
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 5px;
        font-weight: bold;
    }
    .stButton button:hover {
        background-color: #1565c0;
    }
    .sidebar .sidebar-content {
        background-color: #f8f9fa;
    }
    .category-badge {
        display: inline-block;
        background-color: #4caf50;
        color: white;
        padding: 4px 12px;
        border-radius: 15px;
        font-size: 0.9rem;
        margin: 5px;
    }
    .intent-badge {
        display: inline-block;
        background-color: #ff9800;
        color: white;
        padding: 4px 12px;
        border-radius: 15px;
        font-size: 0.9rem;
        margin: 5px;
    }
    </style>
    """, unsafe_allow_html=True)

class GSTChatbot:
    def __init__(self, api_url="http://localhost:8000"):
        self.api_url = api_url
        self.session_id = None
        
    def create_session(self):
        try:
            response = requests.post(f"{self.api_url}/session")
            if response.status_code == 200:
                self.session_id = response.json()["session_id"]
                return True
        except Exception as e:
            st.error(f"Failed to create session: {e}")
        return False
    
    def send_message(self, query, user_category=None):
        if not self.session_id:
            if not self.create_session():
                return None
        
        payload = {
            "query": query,
            "user_category": user_category
        }
        
        try:
            response = requests.post(
                f"{self.api_url}/session/{self.session_id}/query",
                json=payload
            )
            if response.status_code == 200:
                return response.json()
            else:
                st.error(f"API Error: {response.status_code}")
        except Exception as e:
            st.error(f"Failed to send message: {e}")
        
        return None
    
    def get_session_history(self):
        if not self.session_id:
            return []
        
        try:
            response = requests.get(f"{self.api_url}/session/{self.session_id}")
            if response.status_code == 200:
                return response.json()["messages"]
        except Exception as e:
            st.error(f"Failed to get session history: {e}")
        
        return []

def display_message(role, content, timestamp, agent_type=None):
    """Display a chat message with proper styling"""
    if role == "user":
        st.markdown(f"""
        <div class="user-message">
            <strong>You:</strong><br>
            {content}
            <div class="timestamp">{timestamp}</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        agent_badge = f'<span class="agent-badge">{agent_type.upper()}</span>' if agent_type else ""
        st.markdown(f"""
        <div class="assistant-message">
            <strong>GST Assistant {agent_badge}</strong><br>
            {content}
            <div class="timestamp">{timestamp}</div>
        </div>
        """, unsafe_allow_html=True)

def main():
    load_css()
    
    # Initialize chatbot
    if 'chatbot' not in st.session_state:
        st.session_state.chatbot = GSTChatbot()
        st.session_state.chatbot.create_session()
    
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    
    # Header
    st.markdown('<h1 class="main-header">🧠 GST Intelligence Chatbot</h1>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("### 🎯 Configuration")
        
        user_category = st.selectbox(
            "Select Your Category",
            ["business_owner", "accountant", "citizen", "student", "govt_employee", "other"],
            index=0
        )
        
        st.markdown("---")
        st.markdown("### 📊 About")
        st.markdown("""
        This AI-powered chatbot helps you with:
        
        - **Dynamic Updates**: Latest GST news, circulars, and rate changes
        - **Legal Clarifications**: CGST/SGST/IGST Act sections and provisions
        - **Analytical Insights**: Explanations and impact analysis
        
        Powered by multi-agent AI system for accurate GST information.
        """)
        
        if st.button("🔄 New Conversation"):
            st.session_state.chatbot.create_session()
            st.session_state.messages = []
            st.rerun()
        
        st.markdown("---")
        st.markdown("### 💡 Sample Questions")
        
        sample_questions = [
            "What are the latest GST rate changes for restaurants?",
            "Explain Section 16 of CGST Act about input tax credit",
            "How does GST affect small businesses with turnover under 20 lakhs?",
            "What is the current GST rate on electric vehicles?",
            "Explain the difference between CGST, SGST and IGST"
        ]
        
        for question in sample_questions:
            if st.button(f"\"{question}\"", key=question):
                st.session_state.user_input = question
                st.rerun()

    # Main chat area
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown("### 💬 Chat")
        
        # Chat container
        chat_container = st.container()
        
        with chat_container:
            for message in st.session_state.messages:
                display_message(
                    message["role"],
                    message["content"],
                    message["timestamp"],
                    message.get("agent_type")
                )

    with col2:
        st.markdown("### 📈 Session Info")
        
        if st.session_state.messages:
            # Calculate statistics
            user_messages = [m for m in st.session_state.messages if m["role"] == "user"]
            assistant_messages = [m for m in st.session_state.messages if m["role"] == "assistant"]
            
            st.metric("Your Messages", len(user_messages))
            st.metric("AI Responses", len(assistant_messages))
            
            # Show agent distribution
            agent_types = [m.get("agent_type", "unknown") for m in assistant_messages]
            if agent_types:
                st.markdown("**Agents Used:**")
                for agent in set(agent_types):
                    count = agent_types.count(agent)
                    st.markdown(f"- {agent.title()}: {count}")
        else:
            st.info("Start a conversation to see statistics here!")

    # Input area
    st.markdown("---")
    col1, col2 = st.columns([4, 1])
    
    with col1:
        user_input = st.text_area(
            "Your GST Question:",
            key="user_input",
            placeholder="Ask about GST rates, legal provisions, latest updates...",
            height=100
        )
    
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        send_button = st.button("🚀 Send", use_container_width=True)

    # Process user input
    if send_button and user_input.strip():
        # Add user message to chat
        user_message = {
            "role": "user",
            "content": user_input.strip(),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "user_category": user_category
        }
        st.session_state.messages.append(user_message)
        
        # Display user message immediately
        with chat_container:
            display_message("user", user_input.strip(), user_message["timestamp"])
        
        # Get AI response
        with st.spinner("🤔 Analyzing your GST query..."):
            response = st.session_state.chatbot.send_message(user_input.strip(), user_category)
        
        if response:
            # Add assistant message to chat
            assistant_message = {
                "role": "assistant",
                "content": response["final_response"],
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "agent_type": response["target_agent"],
                "query_intent": response["query_intent"],
                "user_category": response["user_category"]
            }
            st.session_state.messages.append(assistant_message)
            
            # Display assistant message with agent info
            with chat_container:
                display_message(
                    "assistant", 
                    response["final_response"], 
                    assistant_message["timestamp"],
                    response["target_agent"]
                )
                
                # Show metadata
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.markdown(f'<span class="category-badge">👤 {response["user_category"].replace("_", " ").title()}</span>', unsafe_allow_html=True)
                with col2:
                    st.markdown(f'<span class="intent-badge">🎯 {response["query_intent"].replace("_", " ").title()}</span>', unsafe_allow_html=True)
                with col3:
                    st.markdown(f'<span class="agent-badge">🤖 {response["target_agent"].title()} Agent</span>', unsafe_allow_html=True)
        
        # Clear input
        st.session_state.user_input = ""
        st.rerun()

    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #666;'>"
        "Powered by Multi-Agent AI System • GST Intelligence API • "
        "For official GST queries, always verify with government sources"
        "</div>", 
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()