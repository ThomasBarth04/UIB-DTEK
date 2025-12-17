from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField, validators


class LoginForm(FlaskForm):
    username = StringField('Username', [validators.data_required()])
    password = PasswordField('Password', [validators.DataRequired()])  # require non-empty
    login = SubmitField('Login')
    next = HiddenField()

