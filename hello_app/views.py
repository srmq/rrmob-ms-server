import logging
from datetime import datetime
from flask import (
    Flask, redirect, request, render_template,
    jsonify, url_for
)
from . import app
from .dbfuncs import (
    create_tables, drop_tables, db_User_exists, db_User_add,
    db_Invitee_idFor, db_Invitee_add, db_put_gmail_send_auth,
    session_scope, db_get_GMailAuth, db_get_GMailAuth_by_state,
    db_get_User_by_email, db_get_SpotifyAuth_by_state,
    db_is_User_email_verified
)
from .dbclasses import User, Invitee, GMailAuthSchema, SpotifyAuth
from spotipy.oauth2 import SpotifyOAuth
import os
import os.path
import uuid
from email.utils import parseaddr
import re, json, hashlib, base64
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import google.auth.transport.requests
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import traceback
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

_root_pass = os.environ.get('ROOT_PASS', '')
if not _root_pass:
    raise Exception("Configuration Error. No ROOT_PASS found")
if len(_root_pass) < 6:
    raise Exception("Configuration Error. ROOT_PASS too weak")
app.config['JWT_SECRET_KEY'] = hashlib.sha512(base64.b64encode((_root_pass).encode())).hexdigest()
_root_pass = None

jwt = JWTManager(app)

my_spotify_scopes = 'user-read-email playlist-read-collaborative user-read-private playlist-modify-public user-top-read playlist-read-private user-follow-read user-read-recently-played playlist-modify-private user-library-read'
client_id = os.environ.get('SPOTIPY_CLIENT_ID', '')
client_secret = os.environ.get('SPOTIPY_CLIENT_SECRET', '')
redirect_uri = os.environ.get('SPOTIPY_REDIRECT_URI', '')

 
def send_confirmation_mail(send_addr, fullname, emailaddr, user_verify_code):
    def create_confirmation_message(to_name, to_address, verification_code):
        plain_message_body = "Olá {fullname}!\n\nPara que possamos confirmar seu endereço de email, precisamos que você visite o seguinte link, clicando sobre ele ou então copiando e colando o endereço em seu navegador: https://rrmob-ms-server.herokuapp.com/confirmemail?u={emailaddr}&c={user_verify_code} .\n\nAgradecemos sua colaboração!\n\nSergio Queiroz\nEquipe RecommenderEffects".format(fullname=fullname, emailaddr=emailaddr, user_verify_code=user_verify_code)
        html_message_body = """\
        <div dir="ltr">Olá {fullname}!<div><br></div><div>Para que 
        possamos confirmar seu endereço de email, precisamos que 
        você visite o seguinte link, clicando sobre ele ou então
        copiando e colando o endereço em seu navegador:
        <a href="https://rrmob-ms-server.herokuapp.com/confirmemail?u={emailaddr}&c={user_verify_code}">
        https://rrmob-ms-server.herokuapp.com/confirmemail?u={emailaddr}&c={user_verify_code}</a></div>
        <div><br></div><div>Agradecemos sua colaboração!</div>
        <div><br></div><div>Sergio Queiroz</div><div><br></div><div>Equipe RecommenderEffects</div></div>
        """.format(fullname=fullname, emailaddr=emailaddr, user_verify_code=user_verify_code)

        plain_message = MIMEText(plain_message_body)
        html_message = MIMEText(html_message_body, 'html')
        message = MIMEMultipart('alternative')
        message['Subject'] = "RecommenderEffects: {0}, por favor, confirme o seu e-mail".format(fullname)
        message['From'] = "srmq@cin.ufpe.br"
        message['To'] = emailaddr
        message.attach(plain_message)
        message.attach(html_message)

        return {'raw': base64.urlsafe_b64encode(message.as_string().encode('utf-8')).decode("utf-8")}

    try:
        with session_scope() as session:
            gmailAuth = db_get_GMailAuth(send_addr, session)
            
            if not gmailAuth:
                return jsonify({"msg": "Misconfiguration error. Gmail address do not have auth info?"}), 500

            creds = Credentials.from_authorized_user_info(gmailAuth.credentials, scopes=gmailAuth.scopes)
            server_request = google.auth.transport.requests.Request()
            creds.refresh(server_request)
            if creds.refresh_token:
                gmailAuth.credentials = json.loads(creds.to_json())

        gmail_service = build('gmail', 'v1', credentials=creds)
        message = create_confirmation_message(fullname, emailaddr, user_verify_code)
        sent_message = (gmail_service.users().messages().send(userId="me", body=message).execute())
        print ("Message Id: " + sent_message['id']) 
    except Exception as e:
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg": "Success"}), 200


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
    my_state = request.args.get('state', default = '', type = str)
    error = request.args.get('error', default = '', type = str)
    if code and my_state and not error:
        try:
            with session_scope() as session:
                log = logging.getLogger()
                log.debug("Received state from spotify was: %s\n", my_state)

                spotifyAuth = db_get_SpotifyAuth_by_state(my_state, session)
                if not spotifyAuth:
                    raise Exception("Invalid state received")
                elif (datetime.now() - spotifyAuth.state_issued_at).total_seconds() > 300:
                    raise Exception("Received state is expired")
                else:
                    sp_oauth = SpotifyOAuth(client_id, client_secret, redirect_uri, state=my_state, scope=my_spotify_scopes)
                    spotifyAuth.token_info = sp_oauth.get_access_token(code)
                    #spotifyAuth.state = None
        except Exception as e:
            msg = "An Error ocurred: " + str(e)
            traceback.print_exc()
            return jsonify({"msg": msg}), 500
        else:
            return redirect(url_for('catch_all', state = my_state))
            #return jsonify({"msg":  "Success"}), 200
    else:
            return jsonify({"msg": "Callback with error: {0}".format(error)}), 400

@app.route("/isemailverified")
@jwt_required
def is_email_verified():
    result = True if db_User_exists(get_jwt_identity()) else False
    return jsonify({"result": result})

@app.route("/spotauthorize")
@jwt_required
def spot_autorize():
    my_state = uuid.uuid4().hex

    sp_oauth = SpotifyOAuth(client_id, client_secret, redirect_uri, state=my_state, scope=my_spotify_scopes)
    auth_url = sp_oauth.get_authorize_url()

    my_state = uuid.uuid4().hex
    state_issued_at = datetime.now()

    try:
        with session_scope() as session:
            email = get_jwt_identity()
            user = db_get_User_by_email(email, session)
            if not user:
                return jsonify({"msg": "Unknown authorized user"}), 500
            if not user.spotify_auth:
                user.spotify_auth = SpotifyAuth(user_id = user.id)
            user.spotify_auth.state = my_state
            user.spotify_auth.state_issued_at = state_issued_at
            log = logging.getLogger()
            log.debug("Recorded state in db was: %s\n", my_state)
    except Exception as e:
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"url": auth_url}), 200


@app.route('/createtables', methods=['POST'])
def create_ddl_db():
    if not request.is_json:
        return jsonify({"msg": "Malformed request, expecting JSON"}), 400
    root_pass = os.environ.get('ROOT_PASS', '')
    rcvd_pass = request.json.get('rootpass', None)
    if not rcvd_pass:
        return jsonify({"msg": "Missing root password parameter"}), 400
    if not rcvd_pass == root_pass:
        return jsonify({"msg": "Invalid root password received"}), 401
    try:
        create_tables()
    except Exception as e:
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg": "Success"}), 200


@app.route('/droptables', methods=['POST'])
def drop_ddl_db():
    if not request.is_json:
        return jsonify({"msg": "Malformed request, expecting JSON"}), 400
    root_pass = os.environ.get('ROOT_PASS', '')
    rcvd_pass = request.json.get('rootpass', None)
    if not rcvd_pass:
        return jsonify({"msg": "Missing root password parameter"}), 400
    if not rcvd_pass == root_pass:
        return jsonify({"msg": "Invalid root password received"}), 401
    try:
        drop_tables()
    except Exception as e:
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg": "Success"}), 200

@app.route('/confirmemail', methods=['GET'])
def confirm_email():
    emailaddr = request.args.get('u', None)
    if not emailaddr:
        return jsonify({"msg": "Missing email address parameter"}), 400    
    
    code = request.args.get('c', None)
    if not code:
        return jsonify({"msg": "Missing confirmation code parameter"}), 400

    try:
        with session_scope() as session:
            user = db_get_User_by_email(emailaddr, session)
            if not user:
                return jsonify({"msg": "Missing confirmation code parameter"}), 400

            if user.email_verified:
                return jsonify({"msg": "Email is already verified"}), 400

            if not user.verify_code == code:
                return jsonify({"msg": "Invalid verification code"}), 400
            
            user.email_verified = True
    except Exception as e:
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg": "Success"}), 200

@app.route('/spotifystatesignin', methods=['POST'])
def spotify_state_signin():
    if not request.is_json:
        return jsonify({"msg": "Malformed request, expecting JSON"}), 400

    state = request.json.get('state', None)
    if not state:
        return jsonify({"msg": "Missing state parameter"}), 400

    try:
        with session_scope() as session:
            spotifyAuth = db_get_SpotifyAuth_by_state(state, session)
            if not spotifyAuth:
                raise Exception("Invalid state received")
            elif (datetime.now() - spotifyAuth.state_issued_at).total_seconds() > 300:
                raise Exception("Received state is expired")
            else:
                spotifyAuth.state = None
                user = spotifyAuth.user
                if not user:
                    return jsonify({"msg": "Invalid user or password"}), 401
                access_token = create_access_token(identity=user.email)
                return jsonify(email=user.email, access_token=access_token), 200            
    except Exception as e:
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500

@app.route('/signin', methods=['POST'])
def signin():
    if not request.is_json:
        return jsonify({"msg": "Malformed request, expecting JSON"}), 400

    email = request.json.get('email', None)
    if not email:
        return jsonify({"msg": "Missing email address parameter"}), 400

    password = request.json.get('password', None)
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    try:
        with session_scope() as session:
            user = db_get_User_by_email(email, session)
            if not user:
                return jsonify({"msg": "Invalid user or password"}), 401
            user_pass_hash = hashlib.sha512(base64.b64encode((password + ":" + user.pass_salt).encode())).hexdigest()
            if not user_pass_hash == user.pass_hash:
                return jsonify({"msg": "Invalid user or password"}), 401
        access_token = create_access_token(identity=email)
        return jsonify(access_token=access_token), 200
    except Exception as e:
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500
            


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

    gmail_addr = os.environ.get('GMAIL_ADDR', '')
    if not gmail_addr:
        return jsonify({"msg": "Misconfiguration error. Missing gmail address?"}), 500

    try:
        if db_User_exists(emailaddr):
            return jsonify({"msg": "User with given email already exists"}), 400

        inviteeId = db_Invitee_idFor(emailaddr)
        if inviteeId is None:
            return jsonify({"msg": "Given email is not on invitee list"}), 400
            
        user_salt = uuid.uuid4().hex
        user_verify_code = uuid.uuid4().hex
        
        user_pass_hash = hashlib.sha512(base64.b64encode((password + ":" + user_salt).encode())).hexdigest()
        new_user = User(fullname = fullname, email = emailaddr, verify_code = user_verify_code, invitee_id = inviteeId, pass_hash = user_pass_hash, pass_salt = user_salt)

        db_User_add(new_user)
        return send_confirmation_mail(gmail_addr, fullname, emailaddr, user_verify_code)
    except Exception as e:
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500

@app.route('/getmyspotifyaccesstoken', methods=['GET'])
@jwt_required
def get_mySpotifyAcessToken():
    user_addr = get_jwt_identity()
    if not user_addr:
        return jsonify({"msg": "Could not find user identity"}), 400

    try:
        with session_scope() as session:
            user = db_get_User_by_email(user_addr, session)
            if not user:
                return jsonify({"msg": "Unknown user"}), 400
            ret = None
            if user.spotify_auth:
                if user.spotify_auth.token_info:
                    sp_oauth = SpotifyOAuth(client_id, client_secret, redirect_uri, scope=my_spotify_scopes)
                    if sp_oauth.is_token_expired(user.spotify_auth.token_info):
                        if 'refresh_token' in user.spotify_auth.token_info:
                            newInfo = sp_oauth.refresh_access_token(user.spotify_auth.token_info['refresh_token'])
                            if 'refresh_token' not in newInfo:
                                newInfo['refresh_token'] = user.spotify_auth.token_info['refresh_token']
                            user.spotify_auth.token_info = newInfo
                    if 'access_token' in user.spotify_auth.token_info:
                        ret = {"access_token": user.spotify_auth.token_info['access_token']}
            return jsonify(ret), 200  
    except Exception as e:
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500

@app.route('/getspotifyauth', methods=['POST'])
def get_SpotifyAuth():
    root_pass = os.environ.get('ROOT_PASS', '')
    if not request.is_json:
        return jsonify({"msg": "Malformed request, expecting JSON"}), 400

    rcvd_pass = request.json.get('rootpass', None)
    if not rcvd_pass:
        return jsonify({"msg": "Missing root password parameter"}), 400
    if not rcvd_pass == root_pass:
        return jsonify({"msg": "Invalid root password received"}), 401

    user_addr = request.json.get('email', None)
    if not user_addr:
        return jsonify({"msg": "Missing email parameter"}), 400

    try:
        with session_scope() as session:
            user = db_get_User_by_email(user_addr, session)
            if not user:
                return jsonify({"msg": "Unknown email"}), 400
            if not user.spotify_auth:
                ret = None
            else:
                ret = user.spotify_auth.token_info
            return jsonify(ret), 200
    except Exception as e:
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500


@app.route('/getgmailauth', methods=['GET'])
def get_GMailAuth():
    root_pass = os.environ.get('ROOT_PASS', '')

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
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500


@app.route('/revalidategmailauth', methods=['GET'])
def revalidate_gmail_auth():
    root_pass = os.environ.get('ROOT_PASS', '')

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
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500
    else:
        return redirect(auth_url)


@app.route("/sendhellomail")
def send_hello_mail():
    root_pass = os.environ.get('ROOT_PASS', '')

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
            return {'raw': base64.urlsafe_b64encode(message.as_string().encode('utf-8')).decode("utf-8")}            
        
        message = create_message("srmq@cin.ufpe.br", "srmq@srmq.org", "RecommenderEffects: por favor, confirme seu e-mail", "Olá mundo!")
        sent_message = (gmail_service.users().messages().send(userId="me", body=message).execute())
        print ("Message Id: " + sent_message['id']) 
    except Exception as e:
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
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
            msg = "An Error ocurred: " + str(e)
            traceback.print_exc()
            return jsonify({"msg": msg}), 500
        else:
            return jsonify({"msg": "Success"}), 200
    else:
            return jsonify({"msg": "Callback with error: {0}".format(error)}), 400


@app.route('/putgmailsendauth', methods=['PUT'])
def put_gmail_send_auth():
    if not request.is_json:
        return jsonify({"msg": "Malformed request, expecting JSON"}), 400

    root_pass = os.environ.get('ROOT_PASS', '')

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
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg": "Success"}), 200


@app.route('/addinvitee', methods=['POST'])
def add_invitee():
    if not request.is_json:
        return jsonify({"msg": "Malformed request, expecting JSON"}), 400
    root_pass = os.environ.get('ROOT_PASS', '')
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
        msg = "An Error ocurred: " + str(e)
        traceback.print_exc()
        return jsonify({"msg": msg}), 500
    else:
        return jsonify({"msg": "Success"}), 200

@app.route('/', defaults={'u_path': ''})
@app.route('/<path:u_path>')
def catch_all(u_path):
    if u_path and os.path.isfile(app.static_folder + "/" + u_path):
        return app.send_static_file(u_path)
    else:
        return app.send_static_file("index.html")
