import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import numpy as np
import re
from tensorflow import keras
from flask import Flask, request, jsonify, render_template
from datetime import datetime

app = Flask(__name__)

# Load the trained model
model = keras.models.load_model("image-Malicious_URL_Prediction.h5")

# Feature extraction functions (as you have defined)
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
        # IPv4
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])|'
        # IPv4 in hex
        r'((0x[0-9a-fA-F]{1,2})\.){3}'
        r'(0x[0-9a-fA-F]{1,2})|'
        # IPv6
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
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

def extract_features(url):
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

# Prediction function
def get_prediction(url):
    features = extract_features(url)
    features = np.array([features])  # Ensure 2D array for model input
    prediction = model.predict(features)
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
    return render_template('IMAGE-CHATBOT.html')


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


@app.route('/chatbot-url')
def chatbot_url():
    # Return the HTML template for URL phishing check
    return render_template('URL-CHATBOT.html')

@app.route('/chatbot-email')
def chatbot_email():
    # Return the HTML template for Email phishing check
    return render_template('EMAIL-CHATBOT.html')

@app.route('/chatbot-image')
def chatbot_image():
    # Return the HTML template for Image phishing check
    return render_template('IMAGE-CHATBOT.html')



# API route for URL analysis
@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    data = request.get_json()
    url = data.get('url') if data else None

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
            probability = get_prediction(image_url)
            # Adding a safety message based on the probability threshold
            safety_status = "Safe" if probability < 50 else "Unsafe"

            # Format the malicious_probability with the safety status included after the %
            malicious_probability = f"{probability:.3f}% ({safety_status})"

            results.append({
                'image_url': image_url,
                'malicious_probability': malicious_probability,  # Includes the safety status
                'safety_status': safety_status  # You can still keep this if you need it separately
            })
        except Exception as e:
            results.append({
                'image_url': image_url,
                'error': str(e)
            })


    return jsonify({"results": results})

if __name__ == '__main__':
    app.run(debug=True)
