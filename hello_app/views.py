import logging
from datetime import datetime
from flask import (
    Flask, redirect, request, render_template,
    jsonify
)
from . import app
from .dbfuncs import (
    create_tables, drop_tables, db_User_exists, db_User_add,
    db_Invitee_idFor, db_Invitee_add, db_put_gmail_send_auth,
    session_scope, db_get_GMailAuth, db_get_GMailAuth_by_state
)
from .dbclasses import User, Invitee, GMailAuthSchema
from spotipy.oauth2 import SpotifyOAuth
import os
import uuid
from email.utils import parseaddr
import re, json
import hashlib, base64
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import google.auth.transport.requests
import requests
from email.mime.text import MIMEText


@app.route("/")
def home():
    return render_template("home.html")

@app.route("/about/")
def about():
    return render_template("about.html")

@app.route("/contact/")
def contact():
    return render_template("contact.html")

@app.route("/privacy/")
def privacy():
    return render_template("privacy.html")

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

    try:
        if db_User_exists(emailaddr):
            return jsonify({"msg": "User with given email already exists"}), 400

        inviteeId = db_Invitee_idFor(emailaddr)
        if inviteeId is None:
            return jsonify({"msg": "Given email is not on invitee list"}), 400
            
        user_salt = uuid.uuid4().hex
        
        user_pass_hash = hashlib.sha512(base64.b64encode((password + ":" + user_salt).encode())).hexdigest()
        new_user = User(fullname = fullname, email = emailaddr, invitee_id = inviteeId, pass_hash = user_pass_hash, pass_salt = user_salt)

        db_User_add(new_user)
    except Exception as e:
        msg = "An Exception ocurred: " + e
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg:": "Success"}), 200

@app.route('/getgmailauth', methods=['GET'])
def get_GMailAuth():
    root_pass = os.environ.get('ROOT_PASS', '')
    if not root_pass:
        return jsonify({"msg": "Misconfiguration error. Missing root password?"}), 500
    elif len(root_pass) < 6:
        return jsonify({"msg": "Misconfiguration error. Root password is too short?"}), 500

    rcvd_pass = request.args.get('rootpass', default = '', type = str)
    if not rcvd_pass:
        return jsonify({"msg": "Missing root password parameter"}), 400
    if not rcvd_pass == root_pass:
        return jsonify({"msg": "Invalid root password received"}), 401

    gmail_addr = os.environ.get('GMAIL_ADDR', '')
    if not gmail_addr:
        return jsonify({"msg": "Misconfiguration error. Missing gmail address?"}), 500
    try:
        with session_scope() as session:
            gmailAuth = db_get_GMailAuth(gmail_addr, session)
            
            if not gmailAuth:
                return jsonify({"msg": "Misconfiguration error. Gmail address do not have auth info?"}), 500
            else:
                gmailAuthSchema = GMailAuthSchema()
                authData = gmailAuthSchema.dump(gmailAuth)
                return jsonify(authData), 200
    except Exception as e:
        msg = "An Error ocurred: " + e
        return jsonify({"msg": msg}), 500


@app.route('/revalidategmailauth', methods=['GET'])
def revalidate_gmail_auth():
    root_pass = os.environ.get('ROOT_PASS', '')
    if not root_pass:
        return jsonify({"msg": "Misconfiguration error. Missing root password?"}), 500
    elif len(root_pass) < 6:
        return jsonify({"msg": "Misconfiguration error. Root password is too short?"}), 500

    rcvd_pass = request.args.get('rootpass', default = '', type = str)
    if not rcvd_pass:
        return jsonify({"msg": "Missing root password parameter"}), 400
    if not rcvd_pass == root_pass:
        return jsonify({"msg": "Invalid root password received"}), 401

    gmail_addr = os.environ.get('GMAIL_ADDR', '')
    if not gmail_addr:
        return jsonify({"msg": "Misconfiguration error. Missing gmail address?"}), 500
    try:
        with session_scope() as session:
            gmailAuth = db_get_GMailAuth(gmail_addr, session)
            
            if not gmailAuth:
                return jsonify({"msg": "Misconfiguration error. Gmail address do not have auth info?"}), 500

            log = logging.getLogger()
            log.debug("Gmail authentication, creating flow. \nClient secrets: %s\nScopes: %s\n", gmailAuth.client_secrets, ' '.join(gmailAuth.scopes))    
            flow = Flow.from_client_config(gmailAuth.client_secrets, ' '.join(gmailAuth.scopes), redirect_uri = gmailAuth.redirect_uri)
            (auth_url, state) = flow.authorization_url()
            gmailAuth.state = state
            gmailAuth.state_issued_at = datetime.now()
    except Exception as e:
        msg = "An Error ocurred: " + e
        return jsonify({"msg": msg}), 500
    else:
        return redirect(auth_url)

@app.route("/sendhellomail")
def send_hello_mail():
    root_pass = os.environ.get('ROOT_PASS', '')
    if not root_pass:
        return jsonify({"msg": "Misconfiguration error. Missing root password?"}), 500
    elif len(root_pass) < 6:
        return jsonify({"msg": "Misconfiguration error. Root password is too short?"}), 500

    rcvd_pass = request.args.get('rootpass', default = '', type = str)
    if not rcvd_pass:
        return jsonify({"msg": "Missing root password parameter"}), 400
    if not rcvd_pass == root_pass:
        return jsonify({"msg": "Invalid root password received"}), 401

    gmail_addr = os.environ.get('GMAIL_ADDR', '')
    if not gmail_addr:
        return jsonify({"msg": "Misconfiguration error. Missing gmail address?"}), 500
    try:
        with session_scope() as session:
            gmailAuth = db_get_GMailAuth(gmail_addr, session)
            
            if not gmailAuth:
                return jsonify({"msg": "Misconfiguration error. Gmail address do not have auth info?"}), 500

            creds = Credentials.from_authorized_user_info(gmailAuth.credentials, scopes=gmailAuth.scopes)
            server_request = google.auth.transport.requests.Request()
            creds.refresh(server_request)
            if creds.refresh_token:
                gmailAuth.credentials = json.loads(creds.to_json())

        gmail_service = build('gmail', 'v1', credentials=creds)
        def create_message(sender, to, subject, message_text):
            """Create a message for an email.

            Args:
                sender: Email address of the sender.
                to: Email address of the receiver.
                subject: The subject of the email message.
                message_text: The text of the email message.

            Returns:
                An object containing a base64url encoded email object.
            """
            message = MIMEText(message_text)
            message['to'] = to
            message['from'] = sender
            message['subject'] = subject
            return {'raw': base64.urlsafe_b64encode(message.as_string())}            
        
        message = create_message("srmq@cin.ufpe.br", "srmq@srmq.org", "RecommenderEffects: por favor, confirme seu e-mail", "Olá mundo!")
        sent_message = (gmail_service.users().messages().send(userId="me", body=message).execute())
        print ("Message Id: %s") % sent_message['id']
    except Exception as e:
        msg = "An Error ocurred: " + e
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg": "Success"}), 200
    

    


@app.route("/gmailcallback")
def gmail_callback():
    code = request.args.get('code', default = '', type = str)
    state = request.args.get('state', default = '', type = str)
    error = request.args.get('error', default = '', type = str)
    if code and state and not error:
        try:
            with session_scope() as session:
                gmailAuth = db_get_GMailAuth_by_state(state, session)
                if not gmailAuth:
                    raise Exception("Invalid state received")
                elif (datetime.now() - gmailAuth.state_issued_at).total_seconds() > 300:
                    raise Exception("Received state is expired")
                else:
                    flow = Flow.from_client_config(gmailAuth.client_secrets, ' '.join(gmailAuth.scopes), redirect_uri = gmailAuth.redirect_uri)
                    flow.fetch_token(code=code)
                    credentials = flow.credentials
                    gmailAuth.credentials = json.loads(credentials.to_json())
        except Exception as e:
            msg = "An Error ocurred: " + e
            return jsonify({"msg": msg}), 500
        else:
            return jsonify({"msg": "Success"}), 200


@app.route('/putgmailsendauth', methods=['PUT'])
def put_gmail_send_auth():
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

    emailaddr = request.json.get('email', None)
    if not emailaddr:
        return jsonify({"msg": "Missing email parameter"}), 400
    elif not '@' in parseaddr(emailaddr)[1]:
        return jsonify({"msg": "Malformed email address"}), 400

    fullname = request.json.get('fullname', None)
    if not fullname:
        return jsonify({"msg": "Missing full name parameter"}), 400
    elif len(fullname) < 2:
        return jsonify({"msg": "Full name parameter is too short"}), 400

    client_secrets = request.json.get('client_secrets', None)
    if not client_secrets:
        return jsonify({"msg": "Missing client_secrets parameter"}), 400

    redirect_uri = request.json.get('redirect_uri', None)
    if not redirect_uri:
        return jsonify({"msg": "Missing redirect_uri parameter"}), 400

    scopes = request.json.get('scopes', None)
    if not scopes:
        return jsonify({"msg": "Missing scopes parameter"}), 400

    try: 
        db_put_gmail_send_auth(request.json)
    except Exception as e:
        msg = "An Error ocurred: " + e
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg": "Success"}), 200


@app.route('/addinvitee', methods=['POST'])
def add_invitee():
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
    emailaddr = request.json.get('email', None)
    if not emailaddr:
        return jsonify({"msg": "Missing email parameter"}), 400
    elif not '@' in parseaddr(emailaddr)[1]:
        return jsonify({"msg": "Malformed email address"}), 400

    try:
        invitee = Invitee(email = emailaddr)
        db_Invitee_add(invitee)
    except Exception as e:
        msg = "An Error ocurred: " + e
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg": "Success"}), 200
