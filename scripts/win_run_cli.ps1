.\.venv\Scripts\Activate.ps1
pytest -q
pqcbench list-algos
pqcbench demo rsa-pss
$env:FLASK_APP = "apps/gui/src/webapp/app.py"
flask run
