from flask import Flask, render_template, request

app = Flask(__name__, static_folder='static', static_url_path='/static')

@app.route('/')
def home():
    return render_template('base.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    plaintext = request.form.get('plaintext')
    if not plaintext:
        return {'status': 'error', 'message': 'No plaintext provided.'}

    # Here’s where you’d call your RSA and Kyber logic:
    rsa_encrypted = f"RSA-512 encrypted: {plaintext[::-1]}"  # Dummy example
    kyber_encrypted = f"Kyber encrypted: {plaintext.upper()}"  # Dummy example

    # For now, just return a simple JSON response
    return {
        'status': 'success',
        'original': plaintext,
        'rsa': rsa_encrypted,
        'kyber': kyber_encrypted
    }

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
