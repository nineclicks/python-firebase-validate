import requests
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography import x509

def _get_certs(url):
    r = requests.get(url)
    certs = r.json()
    return certs

def _get_public_key(pem):
    key = x509.load_pem_x509_certificate(pem,  backend=default_backend())
    public_key = key.public_key()
    return public_key


def decode_firebase_jwt(token,
                      certs_url='https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com',
                      audience=None,
                      certs=None,
                      return_certs=False):

    if certs is None:
        certs = {}
                    
    # Get the token header so we know which cert it was signed with (kid)
    header = jwt.get_unverified_header(token)
    kid = header['kid']

    # If the token kid is not in the provided certs dict then call out to google to get an updated list of certs
    if kid not in certs:
        certs = _get_certs(certs_url)

    # Get the cert specified in our token header as bytes
    # If a matching kid was not provided and it was not found online, will raise KeyError
    cert = certs[kid].encode('ascii')

    # Turn the cert into a public key so the pyjwt can consume it
    # For some reason this is more complicated than passing it a string
    public_key = _get_public_key(cert)
    
    # Get the decoded token if the signature is legit
    # A forged token will raise jwt.exceptions.InvalidSignatureError
    decoded = jwt.decode(token, public_key, algorithms=['RS256'], audience=audience)

    if return_certs:
        # return the decoded token and the used cert list for caching
        return decoded, certs

    else:
        # Just return the decoded token
        return decoded
    
if __name__ == '__main__':
    import sys
    import json

    if len(sys.argv) < 3:
        exit('Usage: {0} <audience/aud> <token>'.format(*sys.argv))

    # audience or "aud". This should be your firebase project name.
    audience = sys.argv[1]

    # the json token returned from firebase auth
    token = sys.argv[2]

    # return certs to cache them. provide certs from some cache and only make request to google if the provided certs are old.
    decoded, certs = decode_firebase_jwt(token, audience=audience, return_certs=True)
    print(json.dumps(decoded, indent=2))
    print(json.dumps(certs, indent=2))
