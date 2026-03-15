from pathlib import Path

from flask import Flask, send_file

app = Flask(__name__)
ROOT_INDEX = Path(__file__).with_name("index.html")


@app.route("/")
def index():
    return send_file(ROOT_INDEX)


if __name__ == "__main__":
    print("Single-file offline app served at http://127.0.0.1:5000")
    app.run(debug=False, host="127.0.0.1", port=5000)
