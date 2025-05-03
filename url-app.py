from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS 
import os
import pickle
import re
import requests
import pandas as pd
from urllib.parse import urlparse
from datetime import datetime

# VirusTotal API key
API_KEY = "b4a0367e017d5104cb932677827301f9f9e1bd8def4cef87372709be14dc7511"

# Load the trained model
with open('url_phishing_model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

app = Flask(__name__)

# Enable CORS for all routes (you can customize this if necessary)
CORS(app)

# VirusTotal API function to check if a URL is malicious
def check_virustotal_api(url):
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {
        "apikey": API_KEY,
        "resource": url
    }
    response = requests.get(api_url, params=params)
    
    if response.status_code == 200:
        result = response.json()
        if result["response_code"] == 1:
            return result["positives"] > 0
    return False

# Enhanced feature extraction function
def extract_features(url):
    features = {}

    # Length of the URL
    features['url_length'] = len(url)

    # Check if URL contains an IP address
    features['has_ip'] = 1 if re.search(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', url) else 0

    # Number of special characters in URL
    features['num_special_chars'] = len(re.findall(r'[!@#$%^&*(),?":{}|<>]', url))

    # Parse the URL
    parsed_url = urlparse(url)

    # Count the number of subdomains
    domain_parts = parsed_url.netloc.split('.')
    features['num_subdomains'] = len(domain_parts) - 2 if len(domain_parts) > 2 else 0

    # Check if the URL uses HTTPS
    features['uses_https'] = 1 if parsed_url.scheme == 'https' else 0

    # Check for common phishing keywords in the URL
    phishing_keywords = ['login', 'verify', 'secure', 'account', 'update', 'bank', 'password']
    features['has_phishing_keywords'] = 1 if any(keyword in url.lower() for keyword in phishing_keywords) else 0

    return pd.DataFrame([features])



@app.route('/')
def serve_html():
    return render_template('URL-CHATBOT.html')

@app.route('/chatbot')
def chatbot():
    return render_template('chatbot.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', current_year=datetime.now().year)

@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html', current_year=datetime.now().year)

@app.route('/services')
def services():
    return render_template('services.html', current_year=datetime.now().year)

@app.route('/contactus')
def contactus():
    return render_template('contactus.html', current_year=datetime.now().year)

@app.route('/login')
def login():
    return render_template('login.html', current_year=datetime.now().year)


@app.route('/chatbot/<category>')
def chatbot_category(category):
    if category == 'url':
        return render_template('URL-CHATBOT.html')
    elif category == 'email':
        return render_template('EMAIL-CHATBOT.html')
    elif category == 'image':
        return render_template('IMAGE-CHATBOT.html')
    else:
        return render_template('chatbot.html')  


# API endpoint to handle URL prediction via JSON
@app.route('/predict-url', methods=['POST'])
def predict_url():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Step 1: Check with VirusTotal
    if check_virustotal_api(url):
        message = f"⚠️ This URL is suspicious: '{url}'. We advise you not to trust or interact with it."
        return jsonify({"prediction": "Phishing", "message": message})

    # Step 2: Use ML model
    features = extract_features(url)
    prediction = model.predict(features)[0]

    if prediction == 1:
        message = f"⚠️ This URL is suspicious: '{url}'. We advise you not to trust or interact with it."
        return jsonify({"prediction": "Phishing", "message": message})
    else:
        message = f"✅ You're safe to proceed — '{url}' seems to be a secure and legitimate site."
        return jsonify({"prediction": "Legitimate", "message": message})

if __name__ == "__main__":
    app.run(debug=True, threaded=True)  # Enable threading for handling multiple requests simultaneously






