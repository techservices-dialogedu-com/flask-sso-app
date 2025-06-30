from flask import Flask, request, make_response
from signxml import XMLSigner, methods
from lxml import etree
import base64
import datetime

app = Flask(__name__)

# Your SSO URLs
ISSUER      = "https://sso.dialogedu.com"
DESTINATION = "https://accounts.zohoportal.com/accounts/csamlresponse/10098904568"

@app.route("/login")
def login():
    # Extract required query params
    email        = request.args.get("email")
    first_name   = request.args.get("firstName")
    last_name    = request.args.get("lastName")
    relay_state  = request.args.get("redirect")

    if not all([email, first_name, last_name, relay_state]):
        return "Missing one or more required parameters: email, firstName, lastName, redirect", 400

    # Timestamps & IDs
    now          = datetime.datetime.utcnow()
    issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    response_id  = "_{}".format(int(now.timestamp()))

    # Build raw SAML Response XML
    xml_template = f"""
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}"
                    Destination="{DESTINATION}">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{ISSUER}</saml:Issuer>
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                      ID="assertion_{response_id}" IssueInstant="{issue_instant}" Version="2.0">
        <saml:Issuer>{ISSUER}</saml:Issuer>
        <saml:Subject>
          <saml:NameID>{email}</saml:NameID>
        </saml:Subject>
        <saml:AttributeStatement>
          <saml:Attribute Name="Email">
            <saml:AttributeValue>{email}</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="FirstName">
            <saml:AttributeValue>{first_name}</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="LastName">
            <saml:AttributeValue>{last_name}</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>
    """

    # Parse & Sign
    xml_tree = etree.fromstring(xml_template.encode("utf-8"))
    key_data  = open("key.pem", "rb").read()
    cert_data = open("cert.pem", "rb").read()

    signer = XMLSigner(
        method=methods.enveloped,             # exactly the enum member your REPL listed
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256"
    )
    signed_xml = signer.sign(xml_tree, key=key_data, cert=cert_data)

    # Base64-encode and render auto-POST form
    b64_response = base64.b64encode(etree.tostring(signed_xml)).decode("utf-8")
    html = f"""
    <html>
    <body onload="document.forms[0].submit()">
      <form method="post" action="{DESTINATION}">
        <input type="hidden" name="SAMLResponse" value="{b64_response}" />
        <input type="hidden" name="RelayState"    value="{relay_state}" />
      </form>
    </body>
    </html>
    """

    response = make_response(html)
    response.headers["Content-Type"] = "text/html"
    return response

@app.route("/logout")
def logout():
    return "You have been logged out."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
