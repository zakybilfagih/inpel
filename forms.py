from wtforms import Form, StringField, SelectField, validators, PasswordField, BooleanField, FileField


class addUserForm(Form):
    username = StringField('Username', validators=[validators.length(4, 10)])
    password = PasswordField('Password', validators=[validators.length(6, 16)])
    email = StringField('Email Address', validators=[validators.email(), validators.input_required()])
    admin = BooleanField('Is Admin', validators=[validators.input_required()])
    fullname = StringField('Full Name', validators=[validators.input_required()])
    profileUrl = StringField('Profile URL', validators=[validators.url(), validators.input_required()])
    affiliation = StringField('Affiliation', validators=[validators.input_required()])


class uploadProfile(Form):
    profilePic = FileField("Profile Image", validators=[validators.input_required()])
