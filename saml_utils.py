import base64
import datetime
from OpenSSL import crypto

def build_saml_response(email, first_name, last_name, destination):
    issue_instant = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Load the certificate
    with open("cert.pem", "rb") as cert_file:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
        cert_b64 = base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)).decode("utf-8")
        cert_b64 = cert_b64.replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----\n", "").replace("\n", "")

    # Build assertion
    assertion = f"""
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    Destination="{destination}" ID="_123" IssueInstant="{issue_instant}" Version="2.0">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sso.dialogedu.com</saml:Issuer>
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" IssueInstant="{issue_instant}">
        <saml:Subject>
          <saml:NameID>{email}</saml:NameID>
        </saml:Subject>
        <saml:AttributeStatement>
          <saml:Attribute Name="Email"><saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute>
          <saml:Attribute Name="FirstName"><saml:AttributeValue>{first_name}</saml:AttributeValue></saml:Attribute>
          <saml:Attribute Name="LastName"><saml:AttributeValue>{last_name}</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
        <saml:Signature>
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </saml:Signature>
      </saml:Assertion>
    </samlp:Response>
    """

    with open("key.pem", "rb") as f:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    # Sign assertion (optional enhancement: use proper XML Signature structure in production)
    signed = crypto.sign(key, assertion.encode("utf-8"), "sha256")
    
    return base64.b64encode(assertion.encode("utf-8")).decode("utf-8")
