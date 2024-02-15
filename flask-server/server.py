from flask import Flask, request,jsonify,session
from flask_bcrypt import Bcrypt
from models import db, User

app = Flask(__name__)

app.secret_key = 'qwer'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///flaskdb.db"

PERMANENT_SESSION_LIFETIME = 1800
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ECHO = True

bcrypt = Bcrypt(app)
db.init_app(app)

with app.app_context():
    db.create_all()
# Members API Route


@app.route("/")
def notFound():
    return "<p>Hello</p>"

@app.route("/members")
def members():
    return {"members": ["Member1","Member2","Member3"]}

@app.route("/signup", methods=["POST"])
def signup():
    email = request.json["email"]
    password = request.json["password"]
 
    user_exists = User.query.filter_by(email=email).first() is not None
 
    if user_exists:
        return jsonify({"error": "Email existe!"}), 409
     
    hashed_password = bcrypt.generate_password_hash(password)
    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
 
    session["user_id"] = new_user.id
 
    return jsonify({
        "id": new_user.id,
        "email": new_user.email
    })

@app.route("/login", methods=["POST"])
def login_user():
    email = request.json["email"]
    password = request.json["password"]
  
    user = User.query.filter_by(email=email).first()
  
    if user is None:
        return jsonify({"error": "Acesso não autorizado!"}), 401
  
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Não autorizado"}), 401
      
    session["user_id"] = user.id
  
    return jsonify({
        "id": user.id,
        "email": user.email
    })


if __name__ == "__main__":
    app.run(debug=True) 