# Author : ph.larduinat (at) wanadoo (dot) fr
# https://github.com/philippelt/lhubic
#
# PYTHON 3.X ONLY
#
# Based on the work of puzzle1536
# hubic wrapper to swift : https://github.com/puzzle1536/hubic-wrapper-to-swift

# License : GPL V3


from os import getenv
from re import search
from urllib.parse import parse_qsl, urlparse
from urllib.parse import urlencode
from getpass import getpass
from stat import S_IRUSR, S_IWUSR
from time import time, strptime, mktime, strftime, localtime, timezone

from requests import get, post, delete
from requests.auth import HTTPBasicAuth, AuthBase
import swiftclient



class HubicAuthFailure(Exception) :
    pass



class HubicTokenFailure(Exception):
    pass



class HubicAccessFailure(Exception):
    pass



class HTTPBearerAuth(AuthBase):

    
    def __init__(self, token):
    
        self.token = token

    
    def __call__(self, r):
        
        auth_string = "Bearer " + self.token
        r.headers['Authorization'] = auth_string
        return r



class Hubic(swiftclient.client.Connection):

    
    def __init__(self, client_id=None, client_secret=None, username=None,
                 password=None, refresh_token=None):

        self.redirect_uri    = "http://localhost:8080/"
        self.token_url       = 'https://api.hubic.com/oauth/token'
        self.auth_url        = 'https://api.hubic.com/oauth/auth'

        self.client_id       = client_id or getenv("HUBIC_CLIENT_ID")
        self.client_secret   = client_secret or getenv("HUBIC_CLIENT_SECRET")
        self.username        = username or getenv("HUBIC_USERNAME")
        self.password        = password or getenv("HUBIC_PASSWORD")
        self.refresh_token   = refresh_token or getenv("HUBIC_REFRESH_TOKEN")

        self.oauth_code      = None
        self.access_token    = None
        self.os_auth_token   = None
        self.os_storage_url  = None
        self.token_expire    = None
        self.os_token_expire = None


    def os_auth(self):

        if self.refresh_token :
            self.refresh()
        else:
            self.auth()
            self.token()

        r = self.hubic_get("/account/credentials").json()
        self.os_auth_token = r["token"]
        self.os_storage_url = r["endpoint"]
        expTime = r["expires"]
        self.os_token_expire = mktime(strptime(expTime[:22]+expTime[23:],"%Y-%m-%dT%H:%M:%S%z"))
        super().__init__(preauthurl=self.os_storage_url, preauthtoken=self.os_auth_token)


    def auth(self):

        if not self.access_token and not self.oauth_code:

            payload = {'client_id' : self.client_id,
                       'redirect_uri' : self.redirect_uri,
                       'scope' : 'usage.r,account.r,getAllLinks.r,credentials.r,activate.w,links.drw',
                       'response_type' : 'code',
                       'state' : 'none'}

            r = get(self.auth_url, params=payload, allow_redirects=False)

            if r.status_code != 200:
                raise HubicAuthFailure("Failed to request authorization code, check app credentials")

            try:
                oauthid = search('(?<=<input type="hidden" name="oauth" value=")[0-9]*', r.text).group(0)
            except:
                raise HubicAuthFailure("Failed to request authorization code, check app credentials")

            payload = {'oauth' : oauthid,
                       'usage': 'r',
                       'account': 'r',
                       'getAllLinks': 'r',
                       'credentials': 'r',
                       'activate': 'w',
                       'links': 'r',
                       'action': 'accepted',
                       'login': self.username,
                       'user_pwd': self.password}

            payload = urlencode(payload) + "&links=w&links=d"

            headers = {'content-type': 'application/x-www-form-urlencoded'}

            r = post(self.auth_url, data=payload, headers=headers, allow_redirects=False)

            try:
                location = urlparse(r.headers['location'])
                self.oauth_code = dict(parse_qsl(location.query))['code']
            except:
                raise HubicAuthFailure("Failed to request authorization code, check user/password")

            return self.oauth_code

    
    def token(self):

        if not self.access_token:

            payload = {'code' : self.oauth_code,
                       'redirect_uri': self.redirect_uri,
                       'grant_type' : 'authorization_code'}

            r = post(self.token_url, payload,
                     auth=HTTPBasicAuth(self.client_id,self.client_secret),
                     allow_redirects=False)

            if r.status_code != 200:
                raise HubicTokenFailure("%s : %s" % (r.json()['error'], r.json()['error_description']))

            try:
                self.refresh_token = r.json()['refresh_token']
                self.access_token  = r.json()['access_token']
                self.token_expire  = time() + r.json()['expires_in']
                self.token_type    = r.json()['token_type']

            except:
                raise HubicTokenFailure

        return self.access_token

    
    def refresh(self):

        payload = {'refresh_token' : self.refresh_token,
                   'grant_type' : 'refresh_token'}

        r = post(self.token_url, payload,
                 auth=HTTPBasicAuth(self.client_id,self.client_secret),
                 allow_redirects=False)

        if r.status_code != 200:
            raise HubicTokenFailure("%s : %s" % (r.json()['error'], r.json()['error_description']))

        try:
            self.access_token  = r.json()['access_token']
            self.token_expire  = time() + r.json()['expires_in']
            self.token_type    = r.json()['token_type']

        except:
            raise HubicTokenFailure

        return self.access_token

    
    def hubic_get(self, hubic_api):

        hubic_api_url = 'https://api.hubic.com/1.0%s' % hubic_api

        if self.access_token:

            if self.token_expire <= time():
                self.refresh()

            bearer_auth = HTTPBearerAuth(self.access_token)
            r = get(hubic_api_url, auth=bearer_auth)

            try:
                # Check if token is still valid
                if r.status_code == 401 and r.json()['error'] == 'invalid_token' and r.json()['error_description'] == 'expired':
                    # Try to renew if possible
                    self.refresh()
                    r = get(hubic_api_url, auth=bearer_auth)

                if r.status_code == 404 or r.status_code == 500:
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['message']))

                if r.status_code != 200:
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['error_description']))

            except:
                raise HubicAccessFailure

            return r

    
    def hubic_post(self, hubic_api, data):

        hubic_api_url = 'https://api.hubic.com/1.0%s' % hubic_api

        if self.access_token:

            if self.token_expire <= time():
                self.refresh()

            headers = {'content-type': 'application/x-www-form-urlencoded'}

            bearer_auth = HTTPBearerAuth(self.access_token)
            r = post(hubic_api_url, data=data, headers=headers, auth=bearer_auth)

            try:
                # Check if token is still valid
                if r.status_code == 401 and r.json()['error'] == 'invalid_token' and r.json()['error_description'] == 'expired':
                    # Try to renew if possible
                    self.refresh()
                    r = post(hubic_api_url, auth=bearer_auth)

                if r.status_code == 404 or r.status_code == 500:
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['message']))

                if r.status_code != 200:
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['error_description']))

            except:
                raise HubicAccessFailure

            return r

    
    def hubic_delete(self, hubic_api):

        hubic_api_url = 'https://api.hubic.com/1.0%s' % hubic_api

        if self.access_token:

            if self.token_expire <= time():
                self.refresh()

            bearer_auth = HTTPBearerAuth(self.access_token)
            r = delete(hubic_api_url, auth=bearer_auth)

            try:
                # Check if token is still valid
                if r.status_code == 401 and r.json()['error'] == 'invalid_token' and r.json()['error_description'] == 'expired':
                    # Try to renew if possible
                    self.refresh()
                    r = post(hubic_api_url, auth=bearer_auth)

                if r.status_code == 404 or r.status_code == 500:
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['message']))

                if r.status_code != 200:
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['error_description']))

            except:
                raise HubicAccessFailure

            return r

