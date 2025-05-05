import streamlit as st
import pickle
import re
import string
import os
import email
import email.header

# Default model path - change this to your actual model path
MODEL_PATH = 'phishing_detection_model.pkl'

# Set page title and configure layout
st.set_page_config(
    page_title="Email Phishing Detector",
    page_icon="🔍",
    layout="centered"
)

# Add custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #1E3A8A;
        margin-top: 2rem;
    }
    .prediction-box {
        padding: 20px;
        border-radius: 5px;
        margin-top: 20px;
    }
    .legitimate {
        background-color: #87ffb0;
        border: 1px solid #16A34A;
    }
    .phishing {
        background-color: #fc9090;
        border: 1px solid #DC2626;
    }
    .probability-meter {
        margin-top: 10px;
        margin-bottom: 20px;     
    }
</style>
""", unsafe_allow_html=True)

# Function to preprocess text
def preprocess_text(text):
    """Function to preprocess text data"""
    # Convert to lowercase
    text = text.lower()
    
    # Remove URLs
    text = re.sub(r'https?://\S+|www\.\S+', '', text)
    
    # Remove HTML tags
    text = re.sub(r'<.*?>', '', text)
    
    # Remove punctuation
    text = text.translate(str.maketrans('', '', string.punctuation))
    
    # Remove numbers
    text = re.sub(r'\d+', '', text)
    
    # Tokenize and rejoin (simplistic approach without NLTK)
    tokens = text.split()
    tokens = [token for token in tokens if len(token) > 2]
    
    # Rejoin tokens
    return ' '.join(tokens)

# Function to extract text from an .eml file
def extract_email_text(eml_file):
    """
    Extract text content from an .eml file
    Returns a dictionary with email details
    """
    try:
        # Read the .eml file
        with open(eml_file, 'rb') as f:
            msg = email.message_from_binary_file(f)
        
        # Initialize email text
        email_text = ""
        
        # Extract subject
        subject = msg.get('Subject', '')
        if subject:
            # Decode subject if it's encoded
            decoded_subject = ''
            for part, encoding in email.header.decode_header(subject):
                if isinstance(part, bytes):
                    decoded_subject += part.decode(encoding or 'utf-8', errors='ignore')
                else:
                    decoded_subject += part
            email_text += f"Subject: {decoded_subject}\n\n"
        
        # Extract body
        if msg.is_multipart():
            # Iterate through parts
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain' or content_type == 'text/html':
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        email_text += payload.decode(charset, errors='ignore')
                    except Exception as e:
                        st.warning(f"Could not decode email part: {e}")
        else:
            # Single part email
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            email_text += payload.decode(charset, errors='ignore')
        
        return email_text
    
    except Exception as e:
        st.error(f"Error processing .eml file: {e}")
        return None

# Load model function with error handling for missing model
def load_model(model_path):
    try:
        # Check if file exists
        if not os.path.exists(model_path):
            st.error(f"Model file not found at {model_path}. Please ensure the model exists.")
            return None
        
        # Load the model
        with open(model_path, 'rb') as f:
            return pickle.load(f)
            
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None

# Function to predict if an email is phishing
def predict_phishing(model, email_text):
    if not email_text.strip():
        return None
    
    if model is None:
        st.error("Model is not loaded. Cannot analyze email.")
        return None
    
    # Process the text first
    processed_text = preprocess_text(email_text)
    
    # Predict using the loaded model
    try:
        # Get probability - position depends on the model output (1 for phishing)
        prob = model.predict_proba([processed_text])[0, 1]
        label = model.predict([processed_text])[0]
        
        return {
            'is_phishing': bool(label),
            'phishing_probability': float(prob),
            'prediction': 'Phishing' if label else 'Legitimate'
        }
    except Exception as e:
        st.error(f"Prediction error: {e}")
        st.info("This could be due to a mismatch between the expected model format and the loaded model.")
        return None

def main():
    # Load the model at the start
    model = load_model(MODEL_PATH)
    
    # App header
    st.markdown("<h1 class='main-header'>Email Phishing Detector</h1>", unsafe_allow_html=True)
    st.write("Upload an .eml file or paste an email to check if it's a phishing attempt")
    
    # File upload for .eml files
    uploaded_eml = st.file_uploader("Upload .eml file", type=["eml"])
    
    # Text area for email input
    email_text = st.text_area("Email Content", height=200, 
                             placeholder="Paste the email content here...")
    
    # Process uploaded .eml file
    if uploaded_eml is not None:
        try:
            # Save the uploaded .eml file temporarily
            with open('temp_uploaded.eml', 'wb') as f:
                f.write(uploaded_eml.getvalue())
            
            # Extract text from .eml file
            extracted_text = extract_email_text('temp_uploaded.eml')
            
            if extracted_text:
                # Update the text area with extracted email content
                email_text = extracted_text
                st.success("Email content successfully extracted from .eml file.")
            
            # Remove temporary file
            os.remove('temp_uploaded.eml')
        except Exception as e:
            st.error(f"Error processing .eml file: {e}")
    
    # Add analyze button
    analyze_button = st.button("Analyze Email")
    
    # Show prediction when button is clicked
    if analyze_button and email_text:
        if model is None:
            st.error("Model could not be loaded. Please check the model file.")
        else:
            with st.spinner("Analyzing email content..."):
                result = predict_phishing(model, email_text)
                
                if result:
                    # Display prediction
                    st.markdown(f"<h2 class='sub-header'>Prediction Result</h2>", unsafe_allow_html=True)
                    
                    # Create colored box based on prediction
                    box_class = "legitimate" if result['prediction'] == 'Legitimate' else "phishing"
                    
                    # Format probability as percentage
                    prob_percentage = f"{result['phishing_probability'] * 100:.1f}%"
                    
                    # Display result in styled box
                    st.markdown(f"""
                    <div class="prediction-box {box_class}">
                        <h3>This email appears to be: <strong>{result['prediction']}</strong></h3>
                        <p>Phishing probability: <strong>{prob_percentage}</strong></p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Show progress bar for phishing probability
                    st.markdown("<div class='probability-meter'>", unsafe_allow_html=True)
                    st.progress(result['phishing_probability'])
                    st.markdown("</div>", unsafe_allow_html=True)
                    
                    # Show interpretation
                    st.subheader("What does this mean?")
                    
                    if result['prediction'] == 'Phishing':
                        st.warning("⚠️ This email shows characteristics commonly found in phishing attempts. Be cautious!")
                        st.markdown("""
                        **Common signs of phishing emails:**
                        - Requests for personal information or credentials
                        - Urgency or threats
                        - Suspicious links or attachments
                        - Poor grammar or spelling
                        - Unusual sender email address
                        """)
                    else:
                        st.success("✅ This email appears to be legitimate based on its content.")
                        st.markdown("""
                        **Even for legitimate emails, always be vigilant:**
                        - Verify the sender's email address
                        - Don't click suspicious links
                        - Never share sensitive information via email
                        """)
    
    # Add sample emails for testing with buttons for easy use
    st.markdown("---")
    st.subheader("Sample Emails for Testing")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Load Phishing Example"):
            phishing_example = """Dear Customer,

We have detected unusual activity in your account. Your account has been temporarily limited until we can verify your information.

Please click the link below to verify your identity and restore your account access:
http://secure-bank-verify.com/login

If you don't verify your account within 24 hours, your account will be permanently suspended.

Thank you,
Security Team"""
            st.session_state['email_text'] = phishing_example
            st.rerun()
            
    with col2:
        if st.button("Load Legitimate Example"):
            legitimate_example = """Hi Team,

Just a reminder about our weekly meeting tomorrow at 10am. Please review the attached report before the meeting so we can discuss the quarterly results.

The agenda items are:
1. Q1 performance review
2. New project planning
3. Team updates

Let me know if you have any questions or want to add anything to the agenda.

Thanks,
Manager"""
            st.session_state['email_text'] = legitimate_example
            st.rerun()
    
    # Initialize session state for email text if not already done
    if 'email_text' in st.session_state:
        st.text_area("Email Content", value=st.session_state['email_text'], height=200, key="email_display")
        # Clear the session state after displaying
        st.session_state.pop('email_text')
    
    # Add information about the application
    st.markdown("---")
    st.subheader("About this application")
    st.markdown("""
    This application uses a machine learning model to analyze email content and detect potential phishing attempts. 
    The model was trained on a dataset of phishing and legitimate emails and can identify patterns commonly found in phishing attempts.
    
    **Note**: While this tool can help identify suspicious emails, it's not 100% accurate. Always use your judgment and follow good security practices.
    
    ### How to use:
    1. Ensure the phishing detection model is available at the specified path
    2. Upload an .eml file OR paste an email into the text area
    3. Click "Analyze Email" to get the prediction
    """)

# Handling session state for examples
if 'email_text' not in st.session_state:
    st.session_state['email_text'] = ""

if __name__ == "__main__":
    main()