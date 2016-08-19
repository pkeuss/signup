#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re

# html boilerplate for the top of every page
page_header = """
<!DOCTYPE html>
<html>
<head>
    <title>Signup Page</title>
    <style type="text/css">
        .error {
            color: red;
        }
    </style>
</head>
<body>
    <h1>
        <a href="/">User Signup</a>
    </h1>
    <br><br>
"""

# html boilerplate for the bottom of every page
page_footer = """
</body>
</html>
"""
#The form that displays all of the signup fields
signup_form="""
<form method="post">
    <label>
        Username:
        <input type="text" name="username" value="%(username)s">
    </label>
    <p class = "error">%(user_error)s</p>
    <br>
    <label>
        Password:
        <input type="password" name="password">
    </label>
    <p class = "error">%(pass_error)s</p>
    <br>
    <label>
        Verify Password:
        <input type="password" name="verify">
    </label>
    <p class = "error">%(verify_error)s</p>
    <br>
    <label>
        Email:
        <input type="text" name="email" value="%(email)s">
    </label>
    <p class = "error">%(email_error)s</p>
    <br>
    <input type="submit">
</form>
"""

#regular expressions used to validate user input
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASS_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

class MainHandler(webapp2.RequestHandler):
    """ Handles requests coming in to '/' (the root of the site)
    """
    #redraws the root page whenever called, made a seperate function from get in order to make use of the error strings
    def write_form(self, username="", email="", user_error="", pass_error="", verify_error="", email_error=""):
        response = page_header + signup_form % {"username": cgi.escape(username, quote = True),
                                        "email": cgi.escape(email, quote = True),
                                        "user_error": user_error,
                                        "pass_error": pass_error,
                                        "verify_error": verify_error,
                                        "email_error": email_error} + page_footer
        self.response.write(response)

    def get(self):
        self.write_form()

    def post(self):

        username = self.request.get('username')
        email = self.request.get('email')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email_error = ""
        user_error = ""
        pass_error = ""
        verify_error = ""
        errors = False

        if username == "":
            user_error = "You left the Username field blank"
            errors = True

        if user_error == "":
            if valid_username(username) == None:
                user_error = "Your user name is invalid"
                errors = True

        if password == "":
            pass_error = "You left the Password field blank"
            errors = True

        if pass_error == "":
            if valid_password(password) == None:
                pass_error = "Your password is invalid"
                errors = True

        if verify == "":
            verify_error = "You left the Verify field blank"
            errors = True

        if password != verify:
            verify_error = "Your Passwords don't match"
            errors = True

        if email != "":
            if valid_email(email) == None:
                email_error = "There is a problem with your email"
                errors = True

        if errors:
            self.write_form(username, email, user_error, pass_error,
            verify_error, email_error)

        else:
            self.redirect("/welcome?username=" + username)


class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        username = self.request.get("username")
        response = ("Hello  '{0}', welcome to my site!").format(username)
        username_response = cgi.escape(response, quote=True)
        self.response.out.write(username_response)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
