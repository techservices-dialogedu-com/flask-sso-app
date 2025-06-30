from flask import Flask, request, render_template
from saml_utils import build_saml_response
import os

app = Flask(__name__)

@app.route("/login", methods=["GET", "POST"])
def login():
    email = request.args.get("email", "john.doe@dialogedu.com")
    first_name = request.args.get("firstName", "John")
    last_name = request.args.get("lastName", "Doe")
    destination = request.args.get("redirect", "https://accounts.zohoportal.com/accounts/csamlresponse/10089904568")
    
    saml_response = build_saml_response(email, first_name, last_name, destination)

    print("=== SAML RESPONSE START ===")
    print(saml_response)
    print("RelayState:", request.args.get("RelayState", ""))
    print("Redirect:", destination)
    print("=== SAML RESPONSE END ===")

    return render_template("response.html", saml_response=saml_response, relay_state=request.args.get("RelayState", ""))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))  # default 8080 just in case
    app.run(host="0.0.0.0", port=port)
