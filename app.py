# app.py
from flask import Flask, render_template, request, jsonify
from analyzer import analyze_page
import os
app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.form or request.json or {}
    url = data.get('url')
    if not url:
        return jsonify({"error":"no URL provided"}), 400
    # normalize scheme
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        report = analyze_page(url)
        return render_template('report.html', report=report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
