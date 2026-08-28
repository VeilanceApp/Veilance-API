import backend.api as api
from flask_cors import CORS

from backend.api import veilance_users_v1

app = api.app
app.register_blueprint(api.veilance_public_v1)
app.register_blueprint(api.veilance_users_v1)
app.register_blueprint(api.veilance_admin_v1)

app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024

CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000, debug=True)
