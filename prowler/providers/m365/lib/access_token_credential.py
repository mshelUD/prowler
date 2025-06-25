import time
import jwt

from azure.core.credentials import TokenCredential
from azure.core.credentials import AccessToken


def extract_exp(access_token: str) -> int:
    try:
        payload = jwt.decode(access_token, options={"verify_signature": False})
        return int(payload.get("exp", time.time() + 3600))
    except Exception:
        return int(time.time() + 3600)


class AccessTokenCredential(TokenCredential):
    def __init__(self, access_token):
        self._access_token = access_token
        self._expires_on = extract_exp(access_token)

    def get_token(self,  *args, **kwargs) -> AccessToken:  # type: ignore
        return AccessToken(self._access_token, self._expires_on)
