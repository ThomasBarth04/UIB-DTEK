from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField, URLField, validators
import re


def strong_password(form, field):
    """Enforce a basic strong-password policy with clear feedback."""
    pwd = field.data or ""
    if pwd == "":
        return
    checks = [
        (len(pwd) >= 8, "at least 8 characters"),
        (re.search(r"[A-Z]", pwd), "an uppercase letter"),
        (re.search(r"[a-z]", pwd), "a lowercase letter"),
        (re.search(r"\d", pwd), "a digit"),
        (re.search(r"[^\w\s]", pwd), "a symbol (e.g., !@#$%)"),
    ]
    missing = [msg for ok, msg in checks if not ok]
    if missing:
        raise validators.ValidationError(
            "Password must include " + ", ".join(missing[:-1]) + 
            (", and " + missing[-1] if len(missing) > 1 else "") + "."
        )

class ProfileForm(FlaskForm):
    name = StringField('Name')
    username = StringField('Username', render_kw={'readonly': True})
    password = PasswordField('Password', [strong_password,validators.equal_to('password_again', message='Passwords must match')])
    password_again = PasswordField('Repeat Password')
    birthdate = DateField('Birth date', [validators.optional()])
    color = StringField('Favourite color')
    picture_url = URLField('Picture URL', [validators.url(), validators.optional()])
    about = TextAreaField('About')
    save = SubmitField('Save changes')

