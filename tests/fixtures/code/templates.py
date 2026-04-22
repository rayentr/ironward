# Template injection + Python-specific fixtures.
from flask import request, Flask
import yaml
import pickle
import subprocess

app = Flask(__name__)

# template-jinja-render-string
def view():
    return render_template_string(request.args.get("tpl"))

# py-pickle-loads-untrusted
def load_state():
    return pickle.loads(request.data)

# py-yaml-load-unsafe
def load_config(s):
    return yaml.load(s)

# py-subprocess-shell-true
def run_cmd(user_input):
    return subprocess.run("ls " + user_input, shell=True)

# py-assert-security-check
def admin_only(user):
    assert is_admin(user)
    return 1

# py-flask-debug-true
if __name__ == "__main__":
    app.run(debug=True)

# py-exec-call
def eval_code(payload):
    exec(request.args.get("code"))
