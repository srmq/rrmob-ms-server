from datetime import datetime
from flask import (
    Flask, redirect, request, render_template,
    jsonify
)
from . import app
from .dbfuncs import (
    create_tables, drop_tables, db_User_exists, db_User_add,
    db_Invitee_get
)
from .dbclasses import User, Invitee
from spotipy.oauth2 import SpotifyOAuth
import os
import uuid
from email.utils import parseaddr
import re
import hashlib, base64

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/about/")
def about():
    return render_template("about.html")

@app.route("/contact/")
def contact():
    return render_template("contact.html")

@app.route("/hello/")
@app.route("/hello/<name>")
def hello_there(name = None):
    return render_template(
        "hello_there.html",
        name=name,
        date=datetime.now()
    )

@app.route("/api/data")
def get_data():
    return app.send_static_file("data.json")

@app.route("/spotcallback")
def spot_callback():
    code = request.args.get('code', default = '', type = str)
    state = request.args.get('state', default = '', type = str)
    error = request.args.get('error', default = '', type = str)
    return render_template(
        "spotcallback.html",
        code=code,
        state=state,
        error=error
    )

@app.route("/login")
def login():
    client_id = os.environ.get('SPOTIPY_CLIENT_ID', '')
    client_secret = os.environ.get('SPOTIPY_CLIENT_SECRET', '')
    redirect_uri = os.environ.get('SPOTIPY_REDIRECT_URI', '')
    my_state = uuid.uuid4().hex
    my_scopes = 'user-read-email playlist-read-collaborative user-read-private playlist-modify-public user-top-read playlist-read-private user-follow-read user-read-recently-played playlist-modify-private user-library-read'


    sp_oauth = SpotifyOAuth(client_id, client_secret, redirect_uri, state=my_state, scope=my_scopes)
    auth_url = sp_oauth.get_authorize_url()
    return redirect(auth_url)

@app.route('/createtables', methods=['POST'])
def create_ddl_db():
    if not request.is_json:
        return jsonify({"msg": "Malformed request, expecting JSON"}), 400
    root_pass = os.environ.get('ROOT_PASS', '')
    if not root_pass:
        return jsonify({"msg": "Misconfiguration error. Missing password?"}), 500
    elif len(root_pass) < 6:
        return jsonify({"msg": "Misconfiguration error. Root password is too short?"}), 500
    rcvd_pass = request.json.get('rootpass', None)
    if not rcvd_pass:
        return jsonify({"msg": "Missing root password parameter"}), 400
    if not rcvd_pass == root_pass:
        return jsonify({"msg": "Invalid root password received"}), 401
    try:
        create_tables()
    except Exception as e:
        msg = "An Exception ocurred: " + e
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg": "Success"}), 200

@app.route('/droptables', methods=['POST'])
def drop_ddl_db():
    if not request.is_json:
        return jsonify({"msg": "Malformed request, expecting JSON"}), 400
    root_pass = os.environ.get('ROOT_PASS', '')
    if not root_pass:
        return jsonify({"msg": "Misconfiguration error. Missing password?"}), 500
    elif len(root_pass) < 6:
        return jsonify({"msg": "Misconfiguration error. Root password is too short?"}), 500
    rcvd_pass = request.json.get('rootpass', None)
    if not rcvd_pass:
        return jsonify({"msg": "Missing root password parameter"}), 400
    if not rcvd_pass == root_pass:
        return jsonify({"msg": "Invalid root password received"}), 401
    try:
        drop_tables()
    except Exception as e:
        msg = "An Exception ocurred: " + e
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg": "Success"}), 200


@app.route('/signup', methods=['POST'])
def signup():
    if not request.is_json:
        return jsonify({"msg": "Malformed request, expecting JSON"}), 400
    
    fullname = request.json.get('fullname', None)
    if not fullname:
        return jsonify({"msg": "Missing full name parameter"}), 400
    elif len(fullname) < 2:
        return jsonify({"msg": "Full name parameter is too short"}), 400

    emailaddr = request.json.get('emailaddr', None)
    if not emailaddr:
        return jsonify({"msg": "Missing email address parameter"}), 400
    elif not '@' in parseaddr(emailaddr)[1]:
        return jsonify({"msg": "Malformed email address"}), 400

    password = request.json.get('password', None)
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    elif len(password) < 6:
        return jsonify({"msg": "Password parameter should have at least 6 characters"}), 400
    elif re.search(r"\d", password) is None:
        return jsonify({"msg": "Password parameter should have at least one digit"}), 400
    elif re.search(r"[A-Z]", password) is None and re.search(r"[a-z]", password) is None:
        return jsonify({"msg": "Password parameter should have at least one letter"}), 400

    if db_User_exists(emailaddr):
        return jsonify({"msg": "User with given email already exists"}), 400

    invitee = db_Invitee_get(emailaddr)
    if invitee is None:
        return jsonify({"msg": "Given email is not on invitee list"}), 400
        
    user_salt = uuid.uuid4().hex
    new_user = User(fullname = fullname, email = emailaddr, invitee_id = invitee.id, pass_hash = hashlib.sha512(base64.b64encode(password) + ":" + user_salt).hexdigest(), pass_salt = user_salt)

    db_User_add(new_user)

    return jsonify({"msg:": "Ok"}), 200