import logging
import os
import atexit
import json
import itertools
import flask
import secrets
import apsw
from base64 import b64decode
from box import Box
from datetime import date
from http import HTTPStatus
from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    redirect,
    request,
    send_from_directory,
    make_response,
    render_template,
    session,
    url_for,
)
import flask_login
from flask_login import LoginManager, UserMixin, current_user, login_required
from urllib.parse import urlparse
from werkzeug.exceptions import HTTPException
from werkzeug.datastructures import WWWAuthenticate
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

from .util import load_or_generate_secrets, setup_logging, footers
from .login_form import LoginForm
from .profile_form import ProfileForm

db: apsw.Connection
app: Flask
oauth: OAuth

################################
# Class to store user info
# UserMixin provides us with an `id` field and the necessary methods (`is_authenticated`, `is_active`, `is_anonymous` and `get_id()`).
# Box makes it behave like a dict, but also allows accessing data with `user.key`.



class User(UserMixin, Box):
    def __init__(self, user_data):
        super().__init__(user_data)

    def save(self):
    # prepare info JSON
        info = json.dumps({k: self[k] for k in self if k not in ["username", "password", "id"]})

    # Only hash password if it's not already hashed
        pwd = self.password
        if not pwd.startswith("pbkdf2:sha256:"):  # Werkzeug default hash prefix
            pwd = generate_password_hash(pwd)

        if "id" in self:
            sql_execute(
                "UPDATE users SET username = ?, password = ?, info = ? WHERE id = ?;",
                (self.username, pwd, info, self.id),
            )
            self.password = pwd  # store hashed password in the object too
        else:
            sql_execute(
                "INSERT INTO users (username, password, info) VALUES (?, ?, ?);",
                (self.username, pwd, info),
            )
            self.id = db.last_insert_rowid()
            self.password = pwd


    def add_token(self, name=""):
        """Add a new access token for a user"""
        token = secrets.token_urlsafe(32)
        sql_execute(
            "INSERT INTO tokens (user_id, token, name) VALUES (?, ?, ?);",
            (self.id, token, name),
        )

    def delete_token(self, token):
        """Delete an access token"""
        sql_execute(
            "DELETE FROM tokens WHERE user_id = ? AND token = ?;",
            (self.id, token),
        )

    def get_tokens(self):
        """Retrieve all access tokens belonging to a user"""
        return sql_execute(
            "SELECT token, name FROM tokens WHERE user_id = ?;",
            (self.id,),
        ).fetchall()
    
    @staticmethod
    def is_buddy(self_id, other_user_id):
        row = sql_execute(
            "SELECT 1 FROM buddies WHERE user1_id = ? AND user2_id = ?",
            (self_id, other_user_id)
        ).fetchone()
        return row is not None


    @staticmethod
    def add_buddy(self, other_user_id):
        sql_execute(
            "INSERT OR IGNORE INTO buddies (user1_id, user2_id) VALUES (?, ?)",
            (other_user_id, self.id)
        )


    @staticmethod
    def get_token_user(token):
        """Retrieve the user who owns a particular access token"""
        row = sql_execute(
            "SELECT user_id FROM tokens WHERE token = ?;",
            (token,),
        ).fetchone()
        if row is not None:
            return User.get_user(row[0])
        return None

    @staticmethod
    def get_user(userid):
        # Accept either numeric ids or usernames; never interpolate directly into SQL.
        if isinstance(userid, int) or (isinstance(userid, str) and userid.isnumeric()):
            row = sql_execute(
                "SELECT id, username, password, info FROM users WHERE id = ?;",
                (int(userid),),
            ).fetchone()
        else:
            row = sql_execute(
                "SELECT id, username, password, info FROM users WHERE username = ?;",
                (userid,),
            ).fetchone()

        if row:
            user = User(json.loads(row[3]))
            user.update({"id": row[0], "username": row[1], "password": row[2]})
            return user
        return None

    @staticmethod
    def get_partial_user(userid):
        if isinstance(userid, int) or (isinstance(userid, str) and userid.isnumeric()):
            row = sql_execute(
                "SELECT id, username FROM users WHERE id = ?;",
                (int(userid),),
            ).fetchone()
        else:
            row = sql_execute(
                "SELECT id, username FROM users WHERE username = ?;",
                (userid,),
            ).fetchone()

        if not row:
            return None

        # row = (id, username)
        user = User({})
        user.update({"id": row[0], "username": row[1]})
        return user


    
    

################################
# Set up app


def create_app(test_config=None):
    global app, oauth
    app = Flask("myface", instance_relative_config=True)
    oauth = OAuth(app)
    load_or_generate_secrets(app)

    oauth.register(
        name="gitlab",
        server_metadata_url=" https://git.app.uib.no/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email"},
    )

    # ensure the instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)

    # Pick appropriate values for these
    # app.config['SESSION_COOKIE_NAME'] =
    # app.config['SESSION_COOKIE_SAMESITE'] =
    # app.config['SESSION_COOKIE_SECURE'] =
    # app.config['SESSION_COOKIE_HTTPONLY'] =

    # You can also load app configuration from a Python file
    if os.environ.get("MYFACE_SETTINGS"):
        app.logger.info("Loading config from %s",
                        os.environ.get("MYFACE_SETTINGS"))
        # file name in environment variable
        app.config.from_envvar("MYFACE_SETTINGS")

    # special config for running tests
    if test_config:
        app.config.from_mapping(test_config)

    # load config from environment variables starting with MYFACE_
    app.config.from_prefixed_env("MYFACE")

    # logging
    # used for numbered log entries
    request_counter = itertools.count(start=0, step=1)
    setup_logging(app)
    logger = app.logger

    # Where to find stuff
    app.template_folder = os.path.normpath(os.path.join(
        app.root_path, app.config.get("TEMPLATE_DIR", "templates")))
    app.static_folder = os.path.normpath(os.path.join(
        app.root_path, app.config.get("STATIC_DIR", "static")))
    logger.setLevel(logging.DEBUG)
    logger.info("Starting MyFace")
    logger.debug("template folder: %s", app.template_folder)
    logger.debug("static folder: %s", app.static_folder)
    logger.debug("instance path: %s", app.instance_path)

    # The secret key enables storing encrypted session data in a cookie (TODO: make a secure random key for this! and don't store it in Git!)
    
    if app.debug and not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = "mY s3kritz"

    # open the database file
    with app.app_context():
        sql_init()

    ################################
    # Set up for login manager
    login_manager = LoginManager()
    login_manager.init_app(app)
    # name of the function / view that generates the login page
    login_manager.login_view = "login"  # type: ignore

    @login_manager.user_loader
    def user_loader(user_id):
        """Called whenever the login manager needs to get the User object for a given user id.

        For example, when it finds the id of a logged in user in the session data (session['_user_id'])
        """
        app.logger.info("looking for user %s", user_id)
        user = User.get_user(user_id)
        if user:
            session["username"] = user.username
        return user

    @login_manager.request_loader
    def request_loader(request):
        """This method is called to get a User object based on a request.

        For example, if using an api key or authentication token rather
        than getting the user name the standard way (from the session cookie)
        """
        # Even though this HTTP header is primarily used for *authentication*
        # rather than *authorization*, it's still called "Authorization".
        auth = request.headers.get("Authorization")

        # If there is not Authorization header, do nothing, and the login
        # manager will deal with it (i.e., by redirecting to a login page)
        if not auth:
            return

        (auth_scheme, auth_params) = auth.split(maxsplit=1)
        auth_scheme = auth_scheme.casefold()
        if auth_scheme == "basic":  # Basic auth has username:password in base64
            # TODO: maybe remove this, it's probably a bad idea to implement Basic authentication anyway
            (uname, passwd) = (
                b64decode(auth_params.encode(errors="ignore")).decode(
                    errors="ignore").split(":", maxsplit=1)
            )
            logger.debug(
                f"Basic auth: %s:%s", uname, passwd
            )  # also a bad idea to include the password in the debug log
            u = User.get_user(uname)
            if u and u.password == passwd:
                return u
        elif auth_scheme == "bearer":  # Bearer auth contains an access token;
            # an 'access token' is a unique string that both identifies
            # and authenticates a user, so no username is provided (unless
            # you encode it in the token – see JWT (JSON Web Token), which
            # encodes credentials and (possibly) authorization info)
            logger.debug(
                f"Bearer auth: %s", auth_params
            )  # probably also a bad idea to print the token in the debug log
            # TODO: implement bearer authentication
        # For other authentication schemes, see
        # https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication

        # If we failed to find a valid Authorized header or valid credentials, fail
        # with "401 Unauthorized" and a list of valid authentication schemes
        # (The presence of the Authorized header probably means we're talking to
        # a program and not a user in a browser, so we should send a proper
        # error message rather than redirect to the login page.)
        # (If an authenticated user doesn't have authorization to view a page,
        # Flask will send a "403 Forbidden" response, so think of
        # "Unauthorized" as "Unauthenticated" and "Forbidden" as "Unauthorized")
        abort(
            HTTPStatus.UNAUTHORIZED,
            www_authenticate=WWWAuthenticate("Basic realm=myface, Bearer"),
        )
    
    def can_view_full_profile(viewer_id, target_id):
        if not viewer_id:  # not logged in
            return False
        if int(viewer_id) == int(target_id):  # your own profile
            return True
        # target has added viewer → viewer may see target fully
        print('enter getJSONReuslt', flush=True) 
        return User.is_buddy(viewer_id, target_id)


    ################################
    # ROUTES – these get called to handle requests
    #
    #    Before we get this far, Flask has set up a session store with a session cookie, Flask-Login
    #    has dealt with authentication stuff (for routes marked `@login_required`), and the
    #    before_request() function has been called
    #
    #    Request data is available as global context variables, so you don't need to pass it
    #    around as arguments:
    #      * request – current request object
    #      * session – current session (stores arbitrary session data in a dict-like object)
    #      * g – can store whatever data you like while processing the current request
    #      * current_user – a User object with the currently logged in user (if any)

    @app.get("/")
    @app.get("/index.html")
    @login_required
    def index_html():
        """Render the home page"""
        # any keyword arguments to render_template will become variables
        # we can use inside the template
        return render_template("home.html", var1="value1")

    @app.get("/info/<name>")
    def info(name: str):
        """"""
        info = footers.get(name)
        if info:
            return render_template("_generic_info.html", info=info)
        else:
            abort(404)

    @app.route("/login/", methods=["GET", "POST"])
    def login():
        """Render (GET) or process (POST) login form"""

        logger.debug("/login/ session: %s", session)

        form = LoginForm()

        if not form.next.data:
            # if we got a `next` query parameter, add it to the form so we can redirect the user back to the page they started on
            form.next.data = flask.request.args.get("next")

        if form.is_submitted():
            logger.debug(
                f"Received form:\n    %s\n%s, errors=%s",
                form.data,
                "INVALID" if not form.validate() else "valid",
                form.errors,
            )
            if form.validate():
                username = form.username.data
                password = form.password.data
                user = user_loader(username)
                if user and check_password_hash(user.password, password):
                    return login_user_and_redirect(user)
                else:
                    logger.error(
                        "Invalid username or password for '%s': user=%s", username, user)
                    flask.flash(f"Invalid username or password!",
                                category='error')
            elif form.errors.get('csrf_token'):
                logger.warning('CSRF timeout')
                flask.flash('Form timed out, please try again',
                            category='warning')
            # other form errors are displayed automatically by the template
        return render_template("login.html", form=form)

    def login_user_and_redirect(user: User):
        # Login and set session cookie
        flask_login.login_user(user)

        logger.info("User %s logged in successfully.", user.username)
        # a 'flash' is a message to the user that can be rendered on the web page
        flask.flash(f"User {user.username} logged in successfully.")

        # we're done; redirect to front page or the page the user tried to visist
        next_url = get_safe_redirect_url() or url_for("index_html")
        logger.info("redirecting to %s", next_url)
        return redirect(next_url)

    @app.get("/logout/")
    def logout():
        if current_user and not current_user.is_anonymous:
            username = current_user.username
            flask_login.logout_user()
            logger.info(f"User {username} logged out successfully.")
        return redirect(url_for("index_html"))

    @app.route("/profile/", methods=["GET", "POST", "PUT"])
    @login_required
    def profile():
        """Display or edit user's profile info"""
        logger.debug("%s /profile/ – current user: %s",
                     request.method, current_user)

        form = ProfileForm()
        if form.is_submitted():
            logger.debug(
                f"Received form:\n    %s\n%s errors=%s",
                form.data,
                "INVALID" if not form.validate() else "valid",
                form.errors,
            )
            if form.validate():
                if form.password.data:  # change password if user set it
                    # TODO: should be protect the user against inadvertent password changes?
                    current_user.password = form.password.data
                if form.birthdate.data:  # change birthday if set
                    current_user.birthdate = form.birthdate.data.isoformat()
                # TODO: do we need additional validation for these?
                current_user.name = form.name.data
                current_user.color = form.color.data
                current_user.picture_url = form.picture_url.data
                current_user.about = form.about.data
                current_user.save()
                logger.info("Updated user %s", current_user.username)
            elif form.errors.get('csrf_token'):
                logger.warning('CSRF timeout')
                flask.flash('Form timed out, please try again',
                            category='warning')
            else:
                pass  # The profile.html template will automatically display any errors in form.errors
        else:  # fill in the form with the user's info
            form.username.data = current_user.username
            form.password.data = ""
            form.password_again.data = ""
            # only set this if we have a valid date
            form.birthdate.data = current_user.get(
                "birthdate") and date.fromisoformat(current_user.get("birthdate"))
            form.name.data = current_user.get("name", "")
            form.color.data = current_user.get("color", "")
            form.picture_url.data = current_user.get("picture_url", "")
            form.about.data = current_user.get("about", "")

        # template variables in action!
        return render_template("profile.html", form=form, user=current_user)

    def buddy_flags(viewer_id, target_id):
        """Return buddy relationship flags: viewer -> target, target -> viewer, and mutual."""
        # viewer added target?
        r1 = sql_execute(
            "SELECT 1 FROM buddies WHERE user1_id = ? AND user2_id = ?;",
            (viewer_id, target_id)
        ).fetchone()

        # target added viewer?
        r2 = sql_execute(
            "SELECT 1 FROM buddies WHERE user1_id = ? AND user2_id = ?;",
            (target_id, viewer_id)
        ).fetchone()

        return bool(r2), bool(r1), bool(r1 and r2)

    @app.get("/users/")
    @login_required
    def get_users():
        """Retrieve the list of users, including buddy flags relative to the current user."""
        rows = sql_execute("SELECT id, username FROM users;").fetchall()

        # Compute buddy relations relative to viewer (current_user)
        added_me= {
            r[0] for r in sql_execute(
                "SELECT user2_id FROM buddies WHERE user1_id = ?;",
                (current_user.id,)
            ).fetchall()
        }
        my_added= {
            r[0] for r in sql_execute(
                "SELECT user1_id FROM buddies WHERE user2_id = ?;",
                (current_user.id,)
            ).fetchall()
        }

        result = []
        for uid, uname in rows:
            user = User({"id": uid, "username": uname})
            # flags consumed by the UI
            user["added_by_me"] = uid in my_added         # me -> them
            user["added_me"]   = uid in added_me          # them -> me
            user["mutual"]     = user["added_by_me"] and user["added_me"]
            result.append(user)

        if prefers_json():
            return jsonify(result)
        else:
            return render_template("_users.html", users=result)

    

    @app.get("/users/<userid>")
    @login_required
    def get_user(userid):
        added_by_me, added_me, mutual = buddy_flags(current_user.id, userid)


        if userid == "me":
            u = current_user
        elif can_view_full_profile(current_user.id,userid):
            u = User.get_user(userid)
        else:
            u = User.get_partial_user(userid)
            
        print(added_by_me,added_me,mutual)
        u["added_by_me"] = added_by_me   # I added them
        u["added_me"] = added_me         # they added me
        u["mutual"] = mutual  
        if u:
            if prefers_json():
                return jsonify(u)
            else:
                return render_template("_users.html", users=[u])
        else:
            abort(404)  # Not found

    ################################
    # OpenID Connect endpoints 

    @app.route("/login/gitlab")
    def login_gitlab():
        redirect_uri = url_for("login_callback", _external=True)
        return oauth.gitlab.authorize_redirect(redirect_uri)

    @app.route("/login/callback")
    def login_callback():
        try:
            token = oauth.gitlab.authorize_access_token()
            userinfo = None
            try:
                userinfo = oauth.gitlab.parse_id_token(token)
            except Exception:
                userinfo = oauth.gitlab.userinfo(token=token)

            if not userinfo:
                flask.flash("Failed to retrieve user info from GitLab.", category="error")
                return redirect(url_for("login"))

            app.logger.debug("OIDC userinfo: %s", userinfo)

            sub = str(userinfo.get("sub") or "")
            username = (
                userinfo.get("preferred_username")
                or userinfo.get("nickname")
                or userinfo.get("username")  # some IdPs include 'username'
                or (userinfo.get("email") and userinfo["email"].split("@", 1)[0])
                or f"user-{sub}"
            )
            display_name = userinfo.get("name") or username
            email = userinfo.get("email")
            picture = userinfo.get("picture")

            user = User.get_user(username)
            if not user:
                user = User({
                    "username": username,
                    "password": secrets.token_urlsafe(32),  # not used for OAuth login
                    "name": display_name,
                    "color": "blue",
                    "picture_url": picture or "",
                    "email": email,
                    "oidc_sub": sub,
                    "oidc_issuer": "git.app.uib.no",
                })
                user.save()
            else:
                user.name = display_name
                if picture:
                    user.picture_url = picture
                if email:
                    user.email = email
                user.oidc_sub = sub
                user.oidc_issuer = "git.app.uib.no"
                user.save()

            return login_user_and_redirect(user)

        except Exception as e:
            app.logger.exception("GitLab OAuth failed")
            flask.flash("GitLab login failed. Please try again.", category="error")
            return redirect(url_for("login"))

    

    @app.post("/buddies/<int:user_id>")
    @login_required
    def add_buddie(user_id: int):
        # Can't buddy yourself
        if user_id == current_user.id:
            abort(400, description="Cannot add yourself as a buddy.")

        # Target must exist
        target = User.get_user(user_id)
        if not target:
            abort(404, description="User not found.")

        # Create one-way relation: current_user -> target
        current_user.add_buddy(current_user,user_id)


        return jsonify({"status": "ok", "user_id": user_id}), 201



    @app.before_request
    def before_request():
        """This will be run at the start of every request, before the route function is called."""
        # used by logger so it's easy to see which messages belong to the same request
        g.log_ref = next(request_counter)
        # can be used to allow particular inline scripts with Content-Security-Policy
        g.csp_nonce = secrets.token_urlsafe(32)

    # Can be used to set HTTP headers on the responses
    @app.after_request
    def after_request(response: Response):
        """This will be run at after the route function returns."""
        csp = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{g.csp_nonce}'; "
        "style-src 'self'; "
        "img-src 'self' data: https:; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'self'"
        )

        response.headers["Content-Security-Policy"] = csp
        return response

    @app.route("/favicon.ico")
    def favicon_ico():
        return send_from_directory(app.static_folder or "", "favicon.ico", mimetype="image/vnd.microsoft.icon")

    # For full RFC2324 compatibilty
    @app.get("/coffee/")
    def nocoffee():
        abort(418)

    @app.route("/coffee/", methods=["POST", "PUT"])
    def gotcoffee():
        return "Thanks!"

    ################################
    # Set up standard template context
    @app.context_processor
    def template_context():
        return dict(footers=footers)

    ################################
    # Request context management

    @app.teardown_appcontext
    def teardown_db(exception):
        """Make sure we close the database cursor"""
        cursor = g.pop("cursor", None)

        if cursor is not None:
            cursor.close()

    ################################
    # Setup for the shell
    # (start with `flask -A myface shell`)

    @app.shell_context_processor
    def history_setup():
        """Save Flask shell command line history in a file."""
        app.logger.debug("history_setup")
        import readline

        histfile = os.path.join(app.instance_path, ".flask_shell_history")
        try:
            readline.read_history_file(histfile)
            # default history len is -1 (infinite), which may grow unruly
            # readline.set_history_length(1000)
        except FileNotFoundError:
            pass

        atexit.register(readline.write_history_file, histfile)
        return {}

    @app.shell_context_processor
    def shell_setup():
        """Make a request context and set up local variables for the shell"""
        app.logger.debug("shell_setup")

        ctx = app.test_request_context()
        ctx.push()

        def define_locals():
            # variables we define here (+ `app` and `g`) will be available when we start the Flask shell
            from .app import db, sql_execute, get_cursor, User, generate_password_hash, get_safe_redirect_url
            from flask import render_template, render_template_string, request, make_response, session
            import json
            import base64

            foo = "bar"

            __scope__ = locals().copy()
            return __scope__  # this dict will become local variables in the shell

        return define_locals()

    ################################
    # Error handling

    # This one intercepts HTTPExceptions.
    # Other exceptions will result in a 500 Internal Server Error, possibly displaying the debugger page
    @app.errorhandler(HTTPException)
    def handle_http_error(e: HTTPException):
        """Intercept exceptions and turn the into JSON if the client has requested a JSON reply"""
        app.logger.error("HTTPException %s %s %s",
                         e.description, dir(e), type(e), exc_info=True)
        if prefers_json():
            response = make_response(
                jsonify(
                    {
                        "status": "error",
                        "error": {
                            "code": e.code,
                            "name": e.name,
                            "description": e.description,
                            "html_description": e.get_description(),
                            "exception": type(e).__name__,
                        },
                    }
                )
            )
            response.status = e.code or 200
            return response
        else:
            return e

    ################################
    # we're at the end of create_app(), need to return the app object
    # logger.debug("init: url map:\n%s", app.url_map)
    return app


###################################################
# Some utility functions


def prefers_json():
    """Returns True if the client requested a JSON response."""
    return request.accept_mimetypes.best_match(["application/json", "text/html"]) == "application/json"


def get_safe_redirect_url():
    """Make sure redirects from the login page are safe"""
    # see discussion at
    # https://stackoverflow.com/questions/60532973/how-do-i-get-a-is-safe-url-function-to-use-with-flask-and-how-does-it-work/61446498#61446498
    next = request.values.get("next")

    if next:
        url = urlparse(next)
        if not url.scheme and not url.netloc:  # ignore attempts to use absolute url
            return url.path  # use only the path
    return None


################################
# For database access

def get_cursor():
    """Use a single database server per request"""
    if "cursor" not in g:
        g.cursor = db.cursor()

    return g.cursor


def sql_execute(stmt, *args, **kwargs):
    """Execute and log SQL statement"""
    app.logger.debug("SQL: %s %s %s", stmt, args or "", kwargs or "")
    return get_cursor().execute(stmt, *args, **kwargs)


def sql_init():
    """Set up connection to SQLite database. Database file will be created and initialised if needed."""
    global db
    db_file = os.path.join(app.instance_path, "users.db")
    app.logger.info('opening database %s', db_file)
    db = apsw.Connection(db_file)
    if db.pragma("user_version") == 0:
        sql_execute(
            """CREATE TABLE IF NOT EXISTS users (
            id integer PRIMARY KEY, 
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            info JSON NOT NULL);"""
        )
        sql_execute(
            """CREATE TABLE IF NOT EXISTS tokens (
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            name TEXT
            );"""
        )
        sql_execute(
            """CREATE TABLE IF NOT EXISTS buddies (
            user1_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            user2_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (user1_id, user2_id)
            );"""
        )
        alice = User(
            {
                "username": "alice",
                "password": "password123",
                "name": "Alice",
                "color": "green",
                "picture_url": "https://git.app.uib.no/uploads/-/system/user/avatar/788/avatar.png",
            }
        )
        alice.save()
        alice.add_token("example")
        bob = User({"username": "bob", "password": "bananas",
                   "name": "Bob", "color": "red"})
        bob.save()
        bob.add_token("test")
        sql_execute(f"INSERT INTO buddies (user1_id, user2_id) VALUES ({
                    alice.id}, {bob.id}), ({bob.id}, {alice.id});")
        # we might need to change the database schema later, so it's a good idea to have a versioin number
        sql_execute("PRAGMA user_version = 1;")
        tom = User({"username": "tom", "password": "tom",
                   "name": "tom", "color": "red"})
        tom.save()
        tom.add_token("test")
