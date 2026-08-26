import backend.api as api
from flask_cors import CORS


app = api.app
app.register_blueprint(api.veilance_v1)

app.config['MAX_COONTENT_LENGTH'] = 4 * 1024 * 1024

CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5132, debug=True)
