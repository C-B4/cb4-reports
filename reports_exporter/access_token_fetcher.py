import urllib
import urllib.error
import urllib.request
import uuid
import requests
from getpass import getpass

from reports_exporter.utils import isEmpty, die, buildUrlQueryParams


class AccessTokenFetcher:
    def __init__(self, logger, args) -> None:
        super().__init__()
        self.logger = logger
        self.args = args

    def get_access_token(self) -> str:
        password = self.args.get("password")
        if isEmpty(password):
            password = getpass('Password: ')
        return self.resolve_user_token(self.args["username"], password)

    def resolve_user_token(self, username, password):
        self.logger.debug("Retrieving Keycloak access token")

        if isinstance(username, (int, float)):
            username = str(username)
        elif isEmpty(username):
            die("No Keycloak access username provided")

        if isinstance(password, (int, float)):
            password = str(password)
        elif isEmpty(password):
            die("No Keycloak access password provided")

        clientId = self.args.get("clientId", None)

        if isEmpty(clientId):
            die("No Keycloak client identifier provided")

        clientIdFormat = self.args.get("clientIdFormat", "ups-installation-%s")
        effectiveClientId = clientIdFormat % clientId

        mode = self.args.get("mode", "STANDARD")
        mode = mode.upper()
        if mode == "STANDARD":
            rsp = self.resolveStandardUserToken(
                username, password, effectiveClientId)
        elif mode == "DIRECT":
            rsp = self.resolveDirectGrantUserToken(
                username, password, effectiveClientId)
        else:
            die("Unknown Keycloak access token retrieval mode: %s" % mode)

        accessToken = rsp.get("access_token", None)
        self.refresh_token = rsp.get("refresh_token", None)
        if isEmpty(accessToken):
            self.logger.error("No access token in Keycloak response: %s" % str(rsp))
            die("No access token returned from Keycloak")

        self.logger.debug("Retrieved Keycloak access token")
        return accessToken

    def resolveStandardUserToken(self, username, password, clientId):
        params = self.resolveStandardUserTokenRequestParameters(clientId)
        redirectUri = urllib.parse.unquote(params['redirectUri'])

        params = self.resolveKeycloakSessionAuthenticationCode(username, password, params)

        code = params.get("code", None)
        if isEmpty(code):
            die("No Keycloak access token session code")

        requestHeaders = {
            "Accepts": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        formData = "&".join(
            (
                "grant_type=authorization_code",
                "code=%s" % code,
                "client_id=%s" % clientId,
                "redirect_uri=%s"% redirectUri
            )
        )

        url = self.resolveKeycloakDirectTokenAccessUrl()
        rsp = self.executeHttpRequest(url, "POST", requestHeaders, formData, asJson=True)
        return rsp["body"]

    def resolveDirectGrantUserToken(self, username, password, clientId):
        # See https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST
        formData = "&".join(
            (
                "grant_type=password",
                "username=%s" % username,
                "password=%s" % password,
                "client_id=%s" % clientId
            )
        )

        requestHeaders = {
            "Accepts": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        url = self.resolveKeycloakDirectTokenAccessUrl()
        rsp = self.executeHttpRequest(url, "POST", requestHeaders, formData)
        return rsp["body"]

    def resolveStandardUserTokenRequestParameters(self, clientId):
        params = {}

        baseUrl = self.resolveKeycloakOpenidAccessUrl() + "/auth"
        locItems = urllib.parse.urlparse(baseUrl)
        ## By default, the quote function is intended for quoting the path
        ##  section of a URL.  Thus, it will not encode '/' - unless we override
        ## the 'safe' string
        redirectUri = urllib.parse.quote(locItems.scheme + "://" + locItems.netloc + "/", safe='')
        params["redirectUri"] = redirectUri

        queryParams = {
            "client_id": clientId,
            "redirect_uri": redirectUri,
            "response_mode": "fragment",
            "response_type": "code",
            "scope": "openid",
            "state": str(uuid.uuid4()),
            "nonce": str(uuid.uuid4())
        }

        url = baseUrl + "?" + buildUrlQueryParams(queryParams)
        params["referer"] = url

        rsp = self.executeHttpRequest(url, "GET", { "Accepts": "*/*" }, None, asJson=False)
        params['loginUrl'] = self.extractKeycloakLoginActionValue(rsp['body'].split('\n'))

        cookies = rsp['cookies']
        params['AUTH_SESSION_ID'] = cookies.get("AUTH_SESSION_ID", None)
        params['KC_RESTART'] = cookies.get("KC_RESTART", None)

        return params

    # Returns { "statusCode": ..., "headers": ..., "body": ..., "cookies": ..., "history": ... } object
    def executeHttpRequest(self, url, verb, headersMap, reqData, cookieJar=None, asJson=True):
        if headersMap is None:
            headersMap = {}

        dataBytes = None
        if not isEmpty(reqData):
            dataBytes = bytes(reqData, 'utf-8')
            headersMap["Content-Length"] = str(len(dataBytes))

        try:
            # InsecureRequestWarning: Unverified HTTPS request is being made.
            requests.packages.urllib3.disable_warnings()

            self.logger.debug("%s %s" % (verb, url))
            connTimeout = self.args.get("connectTimeout", 15)
            rspTimeout = self.args.get("responseTimeout", 30)
            rsp = requests.request(verb, url, headers=headersMap,
                data=dataBytes, cookies=cookieJar, verify=False, timeout=(connTimeout, rspTimeout))
            statusCode = rsp.status_code
            if asJson and (statusCode >= 200) and (statusCode < 300):
                rspContent = rsp.json()
            else:
                rspContent = rsp.text
            # NOTE: we extract the response context regardless of the status code
            # so we can place a debug breakpoint here and see it
            if (statusCode < 200) or (statusCode >= 400):
                raise urllib.error.HTTPError(url, statusCode, "Reason: %s. URL: %s" % (rsp.reason, url), rsp.headers, None)
            result = {
                "statusCode": statusCode,
                "headers": rsp.headers,
                "cookies": rsp.cookies,
                "history": rsp.history,
                "body": rspContent
            }
            return result
        except urllib.error.HTTPError as err:
            self.logger.error("Failed (%d %s) to invoke %s %s" % (err.code, err.msg, verb, url))
            raise err
        except urllib.error.URLError as err:
            self.logger.error("Some unknown error for %s %s: %s" % (verb, url, err.reason))
            raise err

    def resolveKeycloakSessionAuthenticationCode(self, username, password, params):
        url = params['loginUrl']
        if isEmpty(url):
            die("Failed to extract Keycloak login URL value")

        cookies = {}

        sessionId = params.get('AUTH_SESSION_ID', None)
        if isEmpty(sessionId):
            die("No Keycloak session ID cookie present")
        cookies["AUTH_SESSION_ID"] = sessionId

        kcToken = params.get('KC_RESTART', None)
        if isEmpty(kcToken):
            die("No Keycloak restart cookie present")
        cookies["KC_RESTART"] = kcToken

        requestHeaders = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": params["referer"]
        }

        formData = "&".join(("username=%s" % username, "password=%s" % password))

        rsp = self.executeHttpRequest(url, "POST", requestHeaders, formData, cookieJar=cookies, asJson=False)
        redirectHistory = rsp.get("history", None)
        if isEmpty(redirectHistory):
            if "INVALID_USER_PASS" in rsp.get("body", None):
                die("Invalid Username or Password")
            else:
                die("No Keycloak redirection available")

        rdData = redirectHistory[0]
        rdHeaders = rdData.headers
        locHeader = rdHeaders.get("Location", None)
        locItems = urllib.parse.urlparse(locHeader)
        # Response is https://..../#state=...
        queryParams = urllib.parse.parse_qs(locItems.fragment)
        code = queryParams.get("code", None)
        if isinstance(code, list):
            code = code[0]

        return {
            "url": rdData.url,
            "cookies": rsp.get("cookies", None),
            "code": code
        }

    def resolveKeycloakDirectTokenAccessUrl(self):
        return self.resolveKeycloakOpenidAccessUrl() + "/token"

    def resolveKeycloakOpenidAccessUrl(self):
        return self.resolveKeycloakRealmAccessUrl() + "/protocol/openid-connect"

    def resolveKeycloakRealmAccessUrl(self):
        if self.args is None:
            die("No Keycloak access arguments provided")

        protocol = self.args.get("protocol", "https")
        host = self.args.get("host", None)
        if isEmpty(host):
            die("No Keycloak host specified")

        port = self.args.get("port", -1)
        realm = self.args.get("realm", "unifiedpush-installations")
        if port > 0:
            return "%s://%s:%d/auth/realms/%s" % (protocol, host, port, realm)
        else:
            return "%s://%s/auth/realms/%s" % (protocol, host, realm)

    def logout(self, accessToken):
        url = self.resolveKeycloakOpenidAccessUrl() + "/logout"
        clientId = self.args.get("clientId", None)
        requestHeaders = {
            "Authorization": "Bearer %s" % accessToken,
            "Content-Type": "application/x-www-form-urlencoded"
        }

        clientIdFormat = self.args.get("clientIdFormat", "ups-installation-%s")
        effectiveClientId = clientIdFormat % clientId

        payload = "&".join(
            (
                "client_id=%s" % effectiveClientId,
                "refresh_token=%s" % self.refresh_token
            )
        )

        self.executeHttpRequest(url, "POST", requestHeaders, payload, asJson=False)

    def extractKeycloakLoginActionValue(self, lines):
        for l in lines:
            pos = l.find("kcLoginAction")
            if pos < 0:
                continue

            pos = l.find("value=")
            if pos < 0:
                continue

            l = l[pos + 6:]
            pos = l.find(' ')
            l = l[0:pos].strip()
            l = l.replace("&amp;", "&")
            return l

        return None
