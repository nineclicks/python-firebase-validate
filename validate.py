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


def verify_google_jwt(token,
                      certs_url='https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com',
                      audience=None,
                      certs={},
                      return_certs=False):
    header = jwt.get_unverified_header(token)
    kid = header['kid']
    if kid not in certs:
        certs = _get_certs(certs_url)
        cert = certs[kid].encode('ascii')
        public_key = _get_public_key(cert)
    
    decoded = jwt.decode(token, public_key, algorithms=['RS256'], audience=audience)

    if return_certs:
        return decoded, certs
    else:
        return decoded
    
if __name__ == '__main__':
    import sys
    import json

    if len(sys.argv) < 3:
        exit('Usage: {0} <audience/aud> <token>'.format(*sys.argv))

    # audience or "aud"
    audience = sys.argv[1]

    # the json token returned from firebase auth
    token = sys.argv[2]

    # return certs to cache them. provide certs from some cache and only make request to google if the provided certs are old.
    decoded, certs = verify_google_jwt(token, audience=audience, return_certs=True)
    print(json.dumps(decoded, indent=2))
    print(json.dumps(certs, indent=2))
