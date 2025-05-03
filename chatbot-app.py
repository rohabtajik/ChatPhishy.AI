import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import numpy as np
import re
from tensorflow import keras
from flask import Flask, request, jsonify, render_template
from datetime import datetime
import pickle
import pandas as pd
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load models
image_model = keras.models.load_model("image-Malicious_URL_Prediction.h5")
with open('url_phishing_model.pkl', 'rb') as model_file:
    url_model = pickle.load(model_file)

# Feature extraction for URL analysis
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

# VirusTotal API function to check if a URL is malicious
def check_virustotal_api(url):
    API_KEY = "b4a0367e017d5104cb932677827301f9f9e1bd8def4cef87372709be14dc7511"
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": API_KEY, "resource": url}
    response = requests.get(api_url, params=params)

    if response.status_code == 200:
        result = response.json()
        if result["response_code"] == 1:
            return result["positives"] > 0
    return False

# Image feature extraction functions
def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def digit_count(url):
    return sum(1 for i in url if i.isnumeric())

def letter_count(url):
    return sum(1 for i in url if i.isalpha())

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def having_ip_address(url):
    match = re.search(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])|((0x[0-9a-fA-F]{1,2})\.){3}(0x[0-9a-fA-F]{1,2})|(#[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
        url
    )
    return -1 if match else 1

def hostname_length(url):
    return len(urlparse(url).netloc)

def url_length(url):
    return len(urlparse(url).path)

def get_counts(url):
    return [
        url.count('-'),
        url.count('@'),
        url.count('?'),
        url.count('%'),
        url.count('.'),
        url.count('='),
        url.count('http'),
        url.count('https'),
        url.count('www')
    ]

def extract_url_features(url):
    url_features = [
        hostname_length(url),
        url_length(url),
        fd_length(url)
    ]
    url_features.extend(get_counts(url))
    url_features.append(digit_count(url))
    url_features.append(letter_count(url))
    url_features.append(no_of_dir(url))
    url_features.append(having_ip_address(url))
    return url_features

def get_prediction_image(url):
    features = extract_url_features(url)
    features = np.array([features])  # Ensure 2D array for model input
    prediction = image_model.predict(features)
    probability = float(prediction[0][0]) * 100
    return probability

# Web scraping function to get clickable image URLs
def extract_clickable_images(page_url):
    try:
        response = requests.get(page_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return [], str(e)

    soup = BeautifulSoup(response.text, 'html.parser')
    clickable_image_urls = []

    for a_tag in soup.find_all('a', href=True):
        img_tag = a_tag.find('img', src=True)
        if img_tag:
            link_url = urljoin(page_url, a_tag['href'])
            clickable_image_urls.append(link_url)
            if len(clickable_image_urls) == 40:
                break

    return clickable_image_urls, None

# Route to serve the HTML page
@app.route('/')
def index():
    return render_template('chatbot.html')

# Other static routes for pages
@app.route('/chatbot-url')
def chatbot_url():
    return render_template('URL-CHATBOT.html')

@app.route('/chatbot-image')
def chatbot_image():
    return render_template('IMAGE-CHATBOT.html')

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

# API route for URL analysis
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

    # Step 2: Use the ML model for URL phishing detection
    features = extract_features(url)
    prediction = url_model.predict(features)[0]

    if prediction == 1:
        message = f"⚠️ This URL is suspicious: '{url}'. We advise you not to trust or interact with it."
        return jsonify({"prediction": "Phishing", "message": message})
    else:
        message = f"✅ You're safe to proceed — '{url}' seems to be a secure and legitimate site."
        return jsonify({"prediction": "Legitimate", "message": message})

# API route for image URL analysis
@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    clickable_images, error = extract_clickable_images(url)
    if error:
        return jsonify({"error": error}), 400

    if not clickable_images:
        return jsonify({"error": "No clickable images found"}), 400

    results = []
    for image_url in clickable_images:
        try:
            probability = get_prediction_image(image_url)
            safety_status = "Safe" if probability < 50 else "Unsafe"
            malicious_probability = f"{probability:.3f}% ({safety_status})"
            results.append({
                'image_url': image_url,
                'malicious_probability': malicious_probability,
                'safety_status': safety_status
            })
        except Exception as e:
            results.append({
                'image_url': image_url,
                'error': str(e)
            })

    return jsonify({"results": results})

if __name__ == "__main__":
    app.run(debug=True, threaded=True)  # Enable threading for handling multiple requests simultaneously
