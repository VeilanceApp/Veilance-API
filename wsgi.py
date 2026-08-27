import backend.api as api

from flask_cors import CORS


app = api.app
app.register_blueprint(api.veilance_v1)


CORS(app, resources={r"/a*": {"origins": "*"}})
