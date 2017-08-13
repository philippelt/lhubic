from os import getenv
from re import search
from urllib.parse import parse_qsl, urlparse
from urllib.parse import urlencode
from getpass import getpass
from stat import S_IRUSR, S_IWUSR
from time import sleep, time, strptime, mktime, strftime, localtime, timezone
from logging import getLogger

from requests import Session
import swiftclient



REDIRECT_URI  = "http://localhost:8080/"
BASE_URL      = 'https://api.hubic.com/'
TOKEN_URL     = BASE_URL + 'oauth/token'
AUTH_URL      = BASE_URL + 'oauth/auth'
HUBIC_API_URL = BASE_URL + '1.0'
TIMEOUT       = 30 # For Hubic requests



log = getLogger("lhubic")


class HubicAuthFailure(Exception) :
    pass



class HubicTokenFailure(Exception):
    pass



class HubicAccessFailure(Exception):
    pass



class Hubic(swiftclient.client.Connection):

    
    def __init__(self, client_id=None, client_secret=None, username=None,
                 password=None, refresh_token=None):

        self.client_id       = client_id or getenv("HUBIC_CLIENT_ID")
        self.client_secret   = client_secret or getenv("HUBIC_CLIENT_SECRET")
        self.username        = username or getenv("HUBIC_USERNAME")
        self.password        = password or getenv("HUBIC_PASSWORD")
        self.refresh_token   = refresh_token or getenv("HUBIC_REFRESH_TOKEN")

        self.session         = Session()

        self.oauth_code      = None
        self.access_token    = None
        self.os_auth_token   = None
        self.os_storage_url  = None
        self.token_expire    = None
        self.os_token_expire = None


    def os_auth(self):

        if self.refresh_token :
            log.info("os_auth: Refreshing token : %s", self.refresh_token)
            self.refresh()
        else:
            self.auth()

        r = self.hubic_get("/account/credentials").json()
        self.os_auth_token = r["token"]
        log.debug("os_auth: Auth token : %s" % r["token"])
        self.os_storage_url = r["endpoint"]
        expTime = r["expires"]
        self.os_token_expire = mktime(strptime(expTime[:22]+expTime[23:],"%Y-%m-%dT%H:%M:%S%z"))
        super().__init__(preauthurl=self.os_storage_url, preauthtoken=self.os_auth_token, timeout=10)


    def auth(self):

        try:
            del self.session.headers['Authorization']
        except:
            pass

        if not self.access_token and not self.oauth_code:

            params = {'client_id' : self.client_id,
                      'redirect_uri' : REDIRECT_URI,
                      'scope' : 'usage.r,account.r,getAllLinks.r,credentials.r,activate.w,links.drw',
                      'response_type' : 'code',
                      'state' : 'none'}

            r = self.session.get(AUTH_URL, params=params, allow_redirects=False, timeout=TIMEOUT)
            log.debug("auth: Client authentication : %s" % r.status_code)

            if r.status_code != 200:
                raise HubicAuthFailure("Failed to request authorization code, check app credentials")

            try:
                oauthid = search('(?<=<input type="hidden" name="oauth" value=")[0-9]*', r.text).group(0)
            except Exception as e:
                log.error("Authorization code (client) request failure : %s" % e)
                raise HubicAuthFailure("Failed to request authorization code, check app credentials")

            params = {'oauth' : oauthid,
                      'usage': 'r',
                      'account': 'r',
                      'getAllLinks': 'r',
                      'credentials': 'r',
                      'activate': 'w',
                      'links': 'r',
                      'action': 'accepted',
                      'login': self.username,
                      'user_pwd': self.password}

            params = urlencode(params) + "&links=w&links=d"

            headers = {'content-type': 'application/x-www-form-urlencoded'}

            r = self.session.post(AUTH_URL, data=params, headers=headers, allow_redirects=False, timeout=TIMEOUT)
            log.debug("auth: Access grant : %s" % r.status_code)

            try:
                location = urlparse(r.headers['location'])
                self.oauth_code = dict(parse_qsl(location.query))['code']
            except Exception as e:
                log.error("Authorization code (user) request failure : %s" % e)
                raise HubicAuthFailure("Failed to request authorization code, check user/password")

            params = {'code' : self.oauth_code,
                      'redirect_uri': REDIRECT_URI,
                      'grant_type' : 'authorization_code'}

            r = self.session.post(TOKEN_URL, params, auth=(self.client_id, self.client_secret), allow_redirects=False, timeout=TIMEOUT)
            log.debug("token: Authorization : %s" % r.status_code)

            if r.status_code != 200:
                log.error("Token request failure %s : %s" % r.status_code, r.content)
                raise HubicTokenFailure("%s : %s" % (r.json()['error'], r.json()['error_description']))

            try:
                self.refresh_token = r.json()['refresh_token']
                self.access_token  = r.json()['access_token']
                self.token_expire  = time() + r.json()['expires_in']
                self.token_type    = r.json()['token_type']

            except Exception as e :
                log.error("Token request parse failure : %s / %s" % (r.content, e))
                raise HubicTokenFailure

        log.info("token: Access %s , refresh %s" % (self.access_token, self.refresh_token))
        self.session.headers['Authorization'] = "Bearer " + self.access_token

    
    def refresh(self):

        try:
            del self.session.headers['Authorization']
        except:
            pass

        params = {'refresh_token' : self.refresh_token,
                  'grant_type' : 'refresh_token'}

        # Unfortunately there are "200" responses without response content !
        attempt = 3
        while attempt > 0:

            r = self.session.post(TOKEN_URL, params, auth=(self.client_id, self.client_secret), allow_redirects=True, timeout=TIMEOUT)
            log.debug("refresh: grant : %s" % r.status_code)

            if r.status_code != 200:
                log.warning("Error refresh grant %" % r.content)
                raise HubicTokenFailure("%s : %s" % (r.json()['error'], r.json()['error_description']))

            try:
                self.access_token  = r.json()['access_token']
                self.token_expire  = time() + r.json()['expires_in']
                self.token_type    = r.json()['token_type']
                break

            except:
                sleep(60)
                attempt -= 1

        else:
            log.error("refresh : Fail to get grant on refresh token")
            raise HubicTokenFailure("refresh_token status %s/%s" % (r.status_code, r.content))

        self.session.headers['Authorization'] = "Bearer " + self.access_token

    
    def hubic_get(self, hubic_api):

        hubic_url = HUBIC_API_URL + hubic_api

        if self.access_token:

            if self.token_expire <= time():
                self.refresh()
            
            r = self.session.get(hubic_url, timeout=TIMEOUT)

            try:
                # Check if token is still valid
                if r.status_code == 401 and r.json()['error'] == 'invalid_token' and r.json()['error_description'] == 'expired':
                    # Try to renew if possible
                    self.refresh()
                    r = self.session.get(hubic_url, timeout=TIMEOUT)

                if r.status_code == 404 or r.status_code == 500:
                    log.error("Hubic API error : %s" % r.status_code)
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['message']))

                if r.status_code != 200:
                    log.error("Hubic API error : %s" % r.status_code)
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['error_description']))

            except Exception as e:
                log.error("Hubic API exception %s" % e)
                raise HubicAccessFailure

            return r

    
    def hubic_post(self, hubic_api, data):

        hubic_url = HUBIC_API_URL + hubic_api

        if self.access_token:

            if self.token_expire <= time():
                self.refresh()

            headers = {'content-type': 'application/x-www-form-urlencoded'}

            r = self.session.post(hubic_url, data=data, headers=headers, timeout=TIMEOUT)

            try:
                # Check if token is still valid
                if r.status_code == 401 and r.json()['error'] == 'invalid_token' and r.json()['error_description'] == 'expired':
                    # Try to renew if possible
                    self.refresh()
                    r = self.session.post(hubic_url, data=data, headers=headers, timeout=TIMEOUT)

                if r.status_code == 404 or r.status_code == 500:
                    log.error("Hubic API error : %s" % r.status_code)
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['message']))

                if r.status_code != 200:
                    log.error("Hubic API error : %s" % r.status_code)
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['error_description']))

            except Exception as e:
                log.error("Hubic API exception %s" % e)
                raise HubicAccessFailure

            return r

    
    def hubic_delete(self, hubic_api):

        hubic_url = HUBIC_API_URL + hubic_api

        if self.access_token:

            if self.token_expire <= time():
                self.refresh()

            r = self.session.delete(hubic_url, timeout=TIMEOUT)

            try:
                # Check if token is still valid
                if r.status_code == 401 and r.json()['error'] == 'invalid_token' and r.json()['error_description'] == 'expired':
                    # Try to renew if possible
                    self.refresh()
                    r = self.session.delete(hubic_url, timeout=TIMEOUT)

                if r.status_code == 404 or r.status_code == 500:
                    log.error("Hubic API error : %s" % r.status_code)
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['message']))

                if r.status_code != 200:
                    log.error("Hubic API error : %s" % r.status_code)
                    raise HubicAccessFailure("%s : %s" % (r.json()['error'], r.json()['error_description']))

            except Exception as e:
                log.error("Hubic API exception %s" % e)
                raise HubicAccessFailure

            return r
