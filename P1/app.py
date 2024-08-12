from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import openai

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost"}})

@app.route('/')
def home():
    return render_template('Project html.html')

@app.route('/api', methods=['POST'])
def chat():
    user_input = request.json.get('message')
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_input}
        ]
    )
    chatbot_response = response['choices'][0]['message']['content']
    return jsonify({"response": chatbot_response})

if __name__ == '__main__':
    app.run(debug=True)


