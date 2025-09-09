
from __future__ import annotations
from flask import Flask, render_template_string, request
from pqcbench import registry

app = Flask(__name__)

TEMPLATE = '''
<!doctype html>
<title>PQC Demo</title>
<h1>PQC Investigation Demo</h1>
<form method="post">
  <label>Algorithm:
    <select name="algo">
      {% for name in algos %}
        <option value="{{name}}">{{name}}</option>
      {% endfor %}
    </select>
  </label>
  <button type="submit">Run</button>
</form>
{% if output %}
<pre>{{ output }}</pre>
{% endif %}
'''

@app.route("/", methods=["GET", "POST"])
def index():
    output = ""
    if request.method == "POST":
        name = request.form.get("algo", "")
        algo_cls = registry.get(name)
        algo = algo_cls()
        if hasattr(algo, "keygen"):
            pk, sk = algo.keygen()
            if hasattr(algo, "encapsulate"):
                ct, ss = algo.encapsulate(pk)
                _ = algo.decapsulate(sk, ct)
                output = f"[KEM] {name}: ok (placeholder)"
            else:
                sig = algo.sign(sk, b"hello")
                ok = algo.verify(pk, b"hello", sig)
                output = f"[SIG] {name}: verify={ok} (placeholder)"
    return render_template_string(TEMPLATE, algos=registry.list().keys(), output=output)

if __name__ == "__main__":
    app.run(debug=True)
