from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from yandex_music import Client
import zipfile
import os
import re
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_required,
    JWTManager,
)
from radio import Radio

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["JWT_SECRET_KEY"] = (
    "super-secret"  # Замените на сложный секретный ключ в реальном приложении!
)

db = SQLAlchemy(app)
jwt = JWTManager(app)

client = Client().init()

TEMP_DIR = "temp_downloads"
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    yandex_token = db.Column(db.String(256), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        # Если пароль верный, создаём JWT-токен, в payload которого записываем username
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token)
    else:
        return jsonify({"error": "Bad username or password"}), 401


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 409

    new_user = User(username=username)
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "user created successfully"}), 201


@app.route("/add_token", methods=["POST"])
@jwt_required()
def add_token():
      username = get_jwt_identity() # Получаем имя пользователя из JWT-токена
      data = request.get_json()
      yandex_token = data.get('token')
      
      if not yandex_token:
        return jsonify({"error": "Yandex token is required"}), 400

      user = User.query.filter_by(username=username).first()
      if not user:
        return jsonify({"error": "User not found"}), 404
  
      user.yandex_token = yandex_token
      db.session.commit()
      
      return jsonify({"message": "Yandex token added successfully"}), 200

def escape_filename(filename):
    return re.sub(r'[\\/*?:"<>|]', "_", filename)

@app.route("/my_wave_download", methods=["POST"])
@jwt_required()
def my_wave_download():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    if not user.yandex_token:
        return jsonify({"error": "Yandex token not set for this user"}), 403

    client_with_token = Client(user.yandex_token).init()
    radio = Radio(client_with_token)

    data = request.get_json()
    track_number = data.get("track_number", 0)
    if not isinstance(track_number, int) or track_number < 0:
        return jsonify({"error": "Invalid track number"}), 400

    track = radio.start_radio("user:onyourwave", "")
    track_paths = []

    for i in range(track_number if track_number > 0 else 1):
        if not track:
            break
        try:
            filename = escape_filename(f"{', '.join(track.artists_name())} - {track.title}.mp3")
            track_file_path = os.path.join(TEMP_DIR, filename)
            track.download(track_file_path, 'mp3')
            track_paths.append(track_file_path)
            track = radio.play_next()
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    if not track_paths:
        return jsonify({"error": "No tracks downloaded"}), 500

    zip_path = os.path.join(TEMP_DIR, "my_wave_tracks.zip")
    with zipfile.ZipFile(zip_path, 'w') as zf:
        for file_path in track_paths:
            zf.write(file_path, os.path.basename(file_path))
    for file_path in track_paths:
        os.remove(file_path)

    response = send_file(zip_path, as_attachment=True, download_name="my_wave_tracks.zip")
    os.remove(zip_path)
    return response
      

if __name__ == "__main__":
      with app.app_context():
          db.create_all()

      app.run(host="0.0.0.0", port=5000, debug=True)
