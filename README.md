# Python Firebase Validate
Validate a Google Firebase JWT in Python

# Usage
```
python -m pip install -r requirements.txt
python firebase_decode <audience/aud/firebase-project-name> <token>
```

```
from firebase_decode import decode_firebase_jwt
...
decoded, certs = decode_firebase_jwt(token, audience=audience, return_certs=True)
# Certs will either be the certs dict you pass in if it has a "kid" that matches the token
# or an updated certs dict from google/certs_url.
# Optionally provide an alternate certs_url and/or certs dict (like from a cache).
# Will raise jwt.exceptions.InvalidSignatureError if token is bogus or KeyError if
# no matching "kid" is found.
```