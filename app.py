from flask import Flask, request, render_template
from saml_utils import build_saml_response

app = Flask(__name__)

@app.route("/login", methods=["GET", "POST"])
def login():
    email = "john.doe@dialogedu.com"
    first_name = "John"
    last_name = "Doe"
    destination = "https://accounts.zohoportal.com/accounts/csamlresponse/10089904568"

    saml_response = build_saml_response(email, first_name, last_name, destination)
    return render_template("response.html", saml_response=saml_response, relay_state=request.args.get("RelayState", ""))
