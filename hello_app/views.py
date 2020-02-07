from datetime import datetime
from flask import (
    Flask, redirect, request, render_template,
    jsonify
)
from . import app
from spotipy.oauth2 import SpotifyOAuth
import os
import uuid
from email.utils import parseaddr
import re

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

    return jsonify({"msg:": "Ok"}), 200