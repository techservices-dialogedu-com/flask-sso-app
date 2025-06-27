import base64
import datetime
from OpenSSL import crypto

def build_saml_response(email, first_name, last_name, destination):
    issue_instant = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    not_on_or_after = (datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    assertion = f"""
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    Destination="{destination}" ID="_123" IssueInstant="{issue_instant}" Version="2.0">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sso.dialogedu.com</saml:Issuer>
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" IssueInstant="{issue_instant}" Version="2.0">
        <saml:Issuer>https://sso.dialogedu.com</saml:Issuer>

        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{email}</saml:NameID>
        </saml:Subject>

        <saml:Conditions NotBefore="{issue_instant}" NotOnOrAfter="{not_on_or_after}">
          <saml:AudienceRestriction>
            <saml:Audience>https://dialogedu.zohodesk.com</saml:Audience>
          </saml:AudienceRestriction>
        </saml:Conditions>

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

    with open("key.pem", "rb") as f:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    # Note: You may later want to apply XML signing properly with lxml and xmlsec libraries
    signed = crypto.sign(key, assertion.encode("utf-8"), "sha256")

    return base64.b64encode(assertion.encode("utf-8")).decode("utf-8")
