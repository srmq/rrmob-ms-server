from datetime import datetime
from flask import Flask, redirect, request, render_template
from . import app
from spotipy.oauth2 import SpotifyOAuth
import os
import uuid

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