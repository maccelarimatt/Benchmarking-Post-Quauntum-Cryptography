from flask import Flask, render_template, request
from pqcbench import registry

app = Flask(__name__, static_folder='static', static_url_path='/static')

@app.route('/')
def home():
    return render_template('base.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    plaintext = request.form.get('plaintext')
    if not plaintext:
        return {'status': 'error', 'message': 'No plaintext provided.'}

    # Use the registered KEM adapters to produce ciphertexts (demo purpose).
    # Note: KEM encapsulates a random shared secret; this does not encrypt the
    # provided plaintext. We return ciphertext previews to illustrate differences.
    out = {"status": "success", "original": plaintext}

    def kem_ct_preview(algo_name: str):
        try:
            cls = registry.get(algo_name)
            kem = cls()
            pk, sk = kem.keygen()
            ct, ss = kem.encapsulate(pk)
            return {
                "ciphertext_len": len(ct) if isinstance(ct, (bytes, bytearray)) else None,
                "ciphertext_hex_prefix": ct[:24].hex() if isinstance(ct, (bytes, bytearray)) else None,
                "shared_secret_len": len(ss) if isinstance(ss, (bytes, bytearray)) else None,
            }
        except Exception as e:
            return {"error": str(e)}

    out["rsa_oaep"] = kem_ct_preview("rsa-oaep")
    out["kyber"] = kem_ct_preview("kyber")

    return out

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
