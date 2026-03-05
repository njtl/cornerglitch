from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return '<html><body><h1>Flask Target</h1><p>Default config, no hardening.</p></body></html>'

@app.route('/health')
def health():
    return 'ok'

@app.route('/login', methods=['POST'])
def login():
    data = request.get_data(as_text=True)
    return f'<html><body><h1>Login received</h1><pre>{data}</pre></body></html>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
