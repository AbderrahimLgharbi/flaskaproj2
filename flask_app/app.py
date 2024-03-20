from flask import Flask, request, jsonify, json
from datetime import timedelta, datetime, timezone
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, get_jwt, unset_jwt_cookies
# ModuleNotFoundError: No module named 'flask_cors' = pip install Flask-Cors
from flask_cors import CORS
from flask_bcrypt import Bcrypt

from models import db, User

api = Flask(__name__)


api.config['SECRET_KEY'] = "cairo-abdo"
api.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///projectdb.db"

api.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(api)

SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ECHO = True

bcrypt = Bcrypt(api)
CORS(api, supports_credentials=True)
db.init_app(api)

with api.app_context():
    db.create_all()


@api.route("/")
def hello():
    return "<p>Hello</p>"


@api.route("/logintoken", methods=["POST"])
def create_token():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    user = User.query.filter_by(email=email).first()

    if user is None:
        return {
            "error": "Wrong"
        }, 401
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "no authorisation"}), 401
    access_token = create_access_token(identity=email)
    # reponse={"access_token":access_token}

    return jsonify({
        "email": email,
        "access_token": access_token
    })


# @api.route("/signup", methods=["POST"])
# def signup():
#     email = request.json["email"]
#     password = request.json["password"]

#     user_exists = User.query.filter_by(email=email).first() is not None

#     if user_exists:
#         return jsonify({"error": "Email already exists"}), 409

#     hashed_password = bcrypt.generate_password_hash(password)
#     new_user = User(username="qwqw", email=email, password=hashed_password)
#     db.session.add(new_user)
#     db.session.commit()

#     return jsonify({
#         "id": new_user.id,
#         "email": new_user.email
#     })


@api.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            data = response.get_json()
            if type(data) is dict:
                data["access_token"] = access_token
                response.data = json.dumps(data)
        return response
    except (RuntimeError, KeyError):

        return response


@api.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response


@api.route('/profile/<getemail>')
@jwt_required()
def my_profile(getemail):
    print(getemail)
    if not getemail:
        return jsonify({"error": "Unauthorized Access"}), 401

    user = User.query.filter_by(email=getemail).first()

    response_body = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
    }

    return response_body


if __name__ == "__main__":
    api.run(debug=True)
