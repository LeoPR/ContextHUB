from flask import Flask, render_template
import os

# Ajusta a pasta de templates para "template" (sua pasta atual)
app = Flask(__name__, template_folder="template")

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)