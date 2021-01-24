#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Dumps the responses counts per store from mobile dashboard
'''

import base64
import datetime
import json
import os
import requests
import signal
import subprocess
import ssl
import sys
import threading
import time
import traceback
import urllib
import urllib.error
import urllib.request
import uuid

VERSION='1.0'

# ----------------------------------------------------------------------------

def die(msg=None,rc=1):
    """
    Cleanly exits the program with an error message
    """

    if msg:
        sys.stderr.write(msg)
        sys.stderr.write("\n")
        sys.stderr.flush()

    sys.exit(rc)

# ----------------------------------------------------------------------------

def isEmpty(s):
    if (s is None) or (len(s) <= 0):
        return True
    else:
        return False

# ----------------------------------------------------------------------------

def isNumberString(value):
    """
    Checks if value is a string that has only digits - possibly with leading '+' or '-'
    """
    if not value:
        return False

    sign = value[0]
    if (sign == '+') or (sign == '-'):
        if len(value) <= 1:
            return False

        absValue = value[1:]
        return absValue.isdigit()
    else:
        if len(value) <= 0:
            return False
        else:
            return value.isdigit()

def isNumberValue(value):
    return isinstance(value, (int, float))

# ----------------------------------------------------------------------------

def isFloatingPointString(value):
    """
    Checks if value is a string that has only digits - possibly with leading '+' or '-' - AND a single dot
    """
    if isEmpty(value):
        return False

    sign = value[0]
    if (sign == '+') or (sign == '-'):
        if len(value) <= 1:
            return False

        absValue = value[1:]
    else:
        absValue = value

    dotPos = absValue.find('.')
    # Must have a dot and it cannot be the last character
    if (dotPos < 0) or (dotPos == (len(absValue) - 1)):
        return False

    # Must have EXACTLY one dot
    dotCount = absValue.count('.')
    if dotCount != 1:
        return False

    # Make sure both sides of the dot are integer numbers
    intPart = absValue[0:dotPos]
    if not isNumberString(intPart):
        return False

    facPart = absValue[dotPos + 1:]
    # Do not allow 123.-5
    sign = facPart[0]
    if (sign == '+') or (sign == '-'):
        return False

    if not isNumberString(facPart):
        return False

    return True

# ----------------------------------------------------------------------------

def normalizeValue(value):
    """
    Checks if value is 'True', 'False' or all numeric and converts it accordingly
    Otherwise it just returns it

    Args:
        value (str) - String value
    """

    if not value:
        return value

    loCase = value.lower()
    if loCase == "none":
        return None
    elif loCase == "true":
        return True
    elif loCase == "false":
        return False
    elif isNumberString(loCase):
        return int(loCase)
    else:
        return value

# ----------------------------------------------------------------------------

def putIfAbsent(args, key, value):
    if args is None:
        return { "key": value }

    if args.get(key, None) is None:
        args[key] = value

    return args

# ----------------------------------------------------------------------------

def parseCommandLineArguments(args):
    """
    Parses an array of arguments having the format: --name=value. If
    only --name is provided then it is assumed to a TRUE boolean value.
    If the value is all digits, then it is assumed to be a number.

    If the same key is specified more than once, then a list of
    the accumulated values is created. The result is a dictionary
    with the names as the keys and value as their mapped values

    Args:
        args (str[]) - The command line arguments to parse
    """

    valsMap = {}
    if len(args) <= 0:
        return valsMap

    for item in args:
        if not item.startswith("--"):
            raise Exception("Missing option identifier: %s" % item)

        propPair = item[2:]     # strip the prefix
        sepPos = propPair.find('=')

        if sepPos == 0:
            raise Exception("Missing name: %s" % item)
        if sepPos >= (len(propPair) - 1):
            raise Exception("Missing value: %s" % item)

        propName = propPair
        propValue = None
        if sepPos < 0:
            propValue = True
        else:
            propName = propPair[0:sepPos]
            propValue = normalizeValue(propPair[sepPos + 1:])

        targetMap = valsMap
        origPropName = propName
        # check if dotted path - if so, create all the intermediate sub-maps
        if propName.find('.') > 0:
            propPath = propName.split('.')
            lastProp = None
            for p in propPath:
                if lastProp is not None:
                    if not lastProp in targetMap:
                        targetMap[lastProp] = { }

                    targetMap = targetMap[lastProp]

                lastProp = p
            propName = lastProp

        if propName in targetMap:
            die("Property repeated: %s" % origPropName)
        else:
            targetMap[propName] = propValue

    return valsMap

# ----------------------------------------------------------------------------

def mergeCommandLineArguments(args, extraArgs):
    """
    Merges the extra arguments into the original ones provided
    they do not already have a value mapped in the original arguments
    """
    for key,value in extraArgs.items():
        originalValue = args.get(key, None)
        if originalValue is None:
            args[key] = value
        elif isinstance(originalValue, dict):
            mergeCommandLineArguments(originalValue, value)

    return args

# ----------------------------------------------------------------------------

def replacePlaceholders(line, extraProps):
    """
    Replaces any ${xxx} with the value taken either from the extra properties or the environment
    """
    if isEmpty(line):
        return line

    while True:
        startPos = line.find("${")
        if startPos < 0:
            break

        endPos = line.find("}")
        if endPos < startPos:
            raise Exception("Imbalanced placeholder in %s" % line)

        propName = line[startPos + 2:endPos]
        propName = propName.strip()
        if isEmpty(propName):
            raise Exception("Missing placeholder name in %s" % line)

        propValue = extraProps.get(propName, None)
        if propValue is None:
            propValue = os.environ.get(propName, None)
            if propValue is None:
                raise Exception("No replacement found for %s in %s" % (propName, line))

        if startPos > 0:
            prefixFragment = line[0:startPos]
        else:
            prefixFragment = ""
        if endPos < (len(line) - 1):
            suffixFragment = line[endPos+1:]
        else:
            suffixFragment = ""
        line = prefixFragment + str(propValue) + suffixFragment

    return line

# ----------------------------------------------------------------------------

def resolvePathVariables(path):
    """
    Expands ~/xxx and ${XXX} variables
    """
    if isEmpty(path):
        return path

    path = os.path.expanduser(path)
    path = os.path.expandvars(path)
    return path

# ----------------------------------------------------------------------------

# Returns a list of fixed-with sub-strings (except last)
def splitByFixedWidth(s, width):
    if s is None:
        return None

    l = len(s)
    if l <= width:
        return [ s ]

    startPos = 0
    fragments = [ ]
    while startPos < l:
        endPos = startPos + width
        if endPos > l:
            endPos = l
        f = s[startPos:endPos]
        fragments.append(f)
        startPos = endPos

    return fragments

# ----------------------------------------------------------------------------

def _decode_list(data):
    # can happen for internal sub-lists of objects
    if isinstance(data, dict):
        return _decode_dict(data)

    rv = []
    for item in data:
        if isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv

# ----------------------------------------------------------------------------

def _decode_dict(data):
    # can happen for internal sub-lists of objects
    if isinstance(data, list):
        return _decode_list(data)

    rv = {}
    for key, value in data.items():
        if isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value

    return rv

# ----------------------------------------------------------------------------

def loadJsonFile(configFile):
    if isEmpty(configFile):
        return {}

    with open(configFile) as config_file:
        return json.load(config_file, object_hook=_decode_dict);

# ============================================================================

class LogLevel(object):
    def __init__(self, name, value):
        self.levelName = name
        self.levelValue = value

    @property
    def name(self):
        return self.levelName

    @name.setter
    def name(self, value):
        raise NotImplementedError("Log level name is immutable")

    @property
    def value(self):
        return self.levelValue

    @value.setter
    def value(self, number):
        raise NotImplementedError("Log level value is immutable")

    def __str__(self):
        return "%s[%s]" % (self.name % str(self.value))

# ----------------------------------------------------------------------------

class Logger(object):
    # Because of some Python limitations we need to define these here
    OFF=LogLevel('OFF', 10000)
    ERROR=LogLevel('ERROR', 1000)
    WARNING=LogLevel('WARNING', 900)
    INFO=LogLevel('INFO', 800)
    DEBUG=LogLevel('DEBUG', 700)
    TRACE=LogLevel('TRACE', 600)
    ALL=LogLevel('ALL', 0)
    LEVELS=[ OFF, ERROR, WARNING, INFO, DEBUG, TRACE, ALL ]

    def __init__(self, name, threshold, args):
        self.loggerName = name
        self.thresholdLevel = threshold
        self.dateTimeFormat = args.get("log-datetime-format", "%Y-%m-%d %H:%M:%S.%f")
        self.maxStackTraceDepth = args.get("log-stacktrace-depth", 10)

    @property
    def name(self):
        return self.loggerName

    @name.setter
    def name(self,value):
        raise NotImplementedError("Logger name is immutable")

    @property
    def threshold(self):
        return self.thresholdLevel

    @threshold.setter
    def threshold(self, value):
        raise NotImplementedError("Not allowed to modify threshold level for %s" % self.name)

    @property
    def errorEnabled(self):
        return self.levelEnabled(Logger.ERROR)

    @errorEnabled.setter
    def errorEnabled(self, value):
        raise NotImplementedError("Not allowed to modify ERROR enabled state for %s" % self.name)

    def error(self, msg, err=None):
        self.log(Logger.ERROR, msg, err)

    @property
    def warningEnabled(self):
        return self.levelEnabled(Logger.WARNING)

    @warningEnabled.setter
    def warningEnabled(self, value):
        raise NotImplementedError("Not allowed to modify WARNING enabled state for %s" % self.name)

    def warning(self, msg, err=None):
        self.log(Logger.WARNING, msg, err)

    @property
    def infoEnabled(self):
        return self.levelEnabled(Logger.INFO)

    @infoEnabled.setter
    def infoEnabled(self, value):
        raise NotImplementedError("Not allowed to modify INFO enabled state for %s" % self.name)

    def info(self, msg, err=None):
        self.log(Logger.INFO, msg, err)

    @property
    def debugEnabled(self):
        return self.levelEnabled(Logger.DEBUG)

    @debugEnabled.setter
    def debugEnabled(self, value):
        raise NotImplementedError("Not allowed to modify DEBUG enabled state for %s" % self.name)

    def debug(self, msg, err=None):
        self.log(Logger.DEBUG, msg, err)

    @property
    def traceEnabled(self):
        return self.levelEnabled(Logger.TRACE)

    @traceEnabled.setter
    def traceEnabled(self, value):
        raise NotImplementedError("Not allowed to modify TRACE enabled state for %s" % self.name)

    def trace(self, msg, err=None):
        self.log(Logger.TRACE, msg, err)

    def log(self, level, msg, err=None):
        if self.levelEnabled(level):
            self.appendLog(level, msg, err)

    def appendLog(self, level, msg, err=None):
        nowValue = datetime.datetime.now()
        timestamp = nowValue.strftime(self.dateTimeFormat)
        threadName = "unknown"
        thread = threading.current_thread()
        if not thread is None:
            threadName = thread.name

        if msg:
            if '\n' in msg:
                for line in msg.splitlines(False):
                    self.writeLogMessage(level, "%s %s [%s] [%s] %s" % (timestamp, threadName, level.name, self.name, line))
            else:
                self.writeLogMessage(level, "%s %s [%s] [%s] %s" % (timestamp, threadName, level.name, self.name, msg))
        if err:
            self.writeLogMessage(level, "%s %s [%s] [%s] %s: %s" % (timestamp, threadName, level.name, self.name, err.__class__.__name__, str(err)))

            if self.maxStackTraceDepth > 0:
                # TODO this doesn't quite do the job - by the time it is here, most stack trace data is gone...
                traceValue = traceback.format_exc(self.maxStackTraceDepth)
                lines = traceValue.splitlines()
                for traceLine in lines:
                    self.writeLogMessage(level, "%s %s [%s] %s %s" % (timestamp, threadName, level.name, self.name, traceLine))

            if err.__class__.__name__ == "KeyboardInterrupt":
                die("Killed by Control+C")

    def writeLogMessage(self, level, msg):
        raise NotImplementedError("%s#writeLogMessage(%s) not implemented" % (self.__class__.__name__, msg))

    def levelEnabled(self, level):
        if not level or not self.threshold:
            return False
        elif level.value >= self.threshold.value:
            return True
        else:
            return False

    def __str__(self):
        return self.name

    @staticmethod
    def fromLevelName(name):
        if (not name) or (len(name) <= 0):
            return None

        effectiveName = name.upper()
        for level in Logger.LEVELS:
            if level.name == effectiveName:
                return level

        return None

    @staticmethod
    def logHelp(logger, lines):
        if (not lines) or (len(lines) <= 0):
            return

        for line in lines:
            logger.info(line)

# ----------------------------------------------------------------------------

class StreamLogger(Logger):
    def __init__(self, name, threshold, args):
        super(StreamLogger, self).__init__(name, threshold, args)
        self.targetStream = None
        self.autoFlush = args.get("log-auto-flush", True)

    def writeLogMessage(self, level, msg):
        self.targetStream.write("%s\n" % msg)
        if self.autoFlush:
            self.targetStream.flush()

# ----------------------------------------------------------------------------

class ConsoleLogger(StreamLogger):
    def __init__(self, name, threshold, args):
        super(ConsoleLogger, self).__init__(name, threshold, args)
        target = args.get("log-console-target", "stderr").lower()
        if target == "stdout":
            self.targetStream = sys.stdout
        else:
            self.targetStream = sys.stderr

# ----------------------------------------------------------------------------

class LogFactory(object):
    def __init__(self, args):
        self.args = args
        self.threshold = Logger.fromLevelName(args.get("log-threshold", Logger.INFO.name))
        if self.threshold is None:
            self.threshold = LogLevel.OFF

    def getLogger(self, name):
        # TODO add support for more logger types
        return ConsoleLogger(name, self.threshold, self.args)

# ////////////////////////////////////////////////////////////////////////////

# Returns a key=value dictionary
def extractResponseCookies(headers):
    if isEmpty(headers):
        return {}

    cookies = {}
    for name, value in headers.items():
        name = name.lower()
        if name != 'set-cookie':
            continue

        value = value.strip()
        pos = value.find(';')
        if pos > 0:
            value = value[0:pos]
        value = value.strip()

        pos = value.find('=')
        if pos > 0:
            name = value[0:pos].strip()
        else:
            name = value
        cookies[name] = value

    return cookies

# ----------------------------------------------------------------------------

# key/value pairs
def buildUrlQueryParams(queryParams):
    if isEmpty(queryParams):
        return None

    nvPairs = []
    for key, value in queryParams.items():
        if isinstance(value, (int, float, bool)):
            value = str(value)
        nvPairs.append("%s=%s" % (key, value))

    return "&".join(nvPairs)

# ----------------------------------------------------------------------------

# Returns { "statusCode": ..., "headers": ..., "body": ..., "cookies": ..., "history": ... } object
def executeHttpRequest(url, verb, headersMap, reqData, logger, args, cookieJar=None, asJson=True):
    if headersMap is None:
        headersMap = {}

    dataBytes = None
    if not isEmpty(reqData):
        dataBytes = bytes(reqData, 'utf-8')
        headersMap["Content-Length"] = str(len(dataBytes))

    try:
        # InsecureRequestWarning: Unverified HTTPS request is being made.
        requests.packages.urllib3.disable_warnings()

        logger.info("%s %s" % (verb, url))
        connTimeout = args.get("connectTimeout", 15)
        rspTimeout = args.get("responseTimeout", 30)
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
            raise urllib.error.HTTPError(url, statusCode, "Failed: %d" % statusCode, rsp.headers, None)

        result = {
            "statusCode": statusCode,
            "headers": rsp.headers,
            "cookies": rsp.cookies,
            "history": rsp.history,
            "body": rspContent
        }
        return result
    except urllib.error.HTTPError as err:
        logger.error("Failed (%d %s) to invoke %s %s" % (err.code, err.msg, verb, url))
        raise err
    except urllib.error.URLError as err:
        logger.error("Some unknown error for %s %s: %s" % (verb, url, err.reason))
        raise err


def downloadReport(url, verb, headersMap, reqData, logger, args):
    if headersMap is None:
        headersMap = {}

    dataBytes = None
    if not isEmpty(reqData):
        dataBytes = bytes(reqData, 'utf-8')
        headersMap["Content-Length"] = str(len(dataBytes))

    try:
        # InsecureRequestWarning: Unverified HTTPS request is being made.
        requests.packages.urllib3.disable_warnings()

        logger.info("%s %s" % (verb, url))
        connTimeout = args.get("connectTimeout", 15)
        rspTimeout = args.get("responseTimeout", 3000)
        rsp = requests.request(verb, url, headers=headersMap,
               data=dataBytes, verify=False, timeout=(connTimeout, rspTimeout))
        statusCode = rsp.status_code
        if (statusCode < 200) or (statusCode >= 400):
            raise urllib.error.HTTPError(url, statusCode, "Failed: %d" % statusCode, rsp.headers, None)

        filePath = resolveOutputFilePath(args)
        text_file = open(filePath, "wb")
        for chunk in rsp.iter_content(chunk_size=1024):
            text_file.write(chunk)

        text_file.close()
    except urllib.error.HTTPError as err:
        logger.error("Failed (%d %s) to invoke %s %s" % (err.code, err.msg, verb, url))
        raise err
    except urllib.error.URLError as err:
        logger.error("Some unknown error for %s %s: %s" % (verb, url, err.reason))
        raise err


# ----------------------------------------------------------------------------

def resolveKeycloakRealmAccessUrl(args):
    if args is None:
        die("No Keycloak access arguments provided")

    protocol = args.get("protocol", "https")
    host = args.get("host", None)
    if isEmpty(host):
        die("No Keycloak host specified")

    port = args.get("port", -1)
    realm = args.get("realm", "unifiedpush-installations")
    if port > 0:
        return "%s://%s:%d/auth/realms/%s" % (protocol, host, port, realm)
    else:
        return "%s://%s/auth/realms/%s" % (protocol, host, realm)

def resolveKeycloakOpenidAccessUrl(args):
    return resolveKeycloakRealmAccessUrl(args) + "/protocol/openid-connect"

# Returns a full URL
def resolveKeycloakDirectTokenAccessUrl(args):
    return resolveKeycloakOpenidAccessUrl(args) + "/token"

def resolveDirectGrantUserToken(username, password, clientId, logger, args):
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

    url = resolveKeycloakDirectTokenAccessUrl(args)
    rsp = executeHttpRequest(url, "POST", requestHeaders, formData, logger, args)
    return rsp["body"]

# ----------------------------------------------------------------------------

def extractKeycloakLoginActionValue(lines):
    for l in lines:
        pos = l.find("kcLoginAction")
        if pos < 0:
            continue

        pos = l.find("value=")
        if pos < 0:
            continue

        l = l[pos+6:]
        pos = l.find(' ')
        l = l[0:pos].strip()
        l = l.replace("&amp;", "&")
        return l

    return None

# GET https://...host.../auth/realms/${realm:unifiedpush-installations}/protocol/openid-connect/auth
#        ? client_id=ups-installation-...client-id...
#        & redirect_uri=https%3A%2F%2F....host....%2F
#        & state=857e7ca8-998c-45cc-aa6b-4e1f92054af5    -- some UUID
#        & response_mode=fragment
#        & response_type=code
#        & scope=openid
#        & nonce=bbf4fc80-0051-4c0a-96d1-4201795a8868    -- some UUID
#
# We need to extract 2 things from the response
#
#    1. AUTH_SESSION_ID and KC_RESTART cookies
#    2. Parse the HTML form body and extract the value of the 'kcLoginAction' input
#
# Return value:
#    {
#        "redirectUri": ... the same redirect URI used in the GET request query parameter ...
#        "referer": ... the full URL used in the GET request ...
#        "loginUrl": ... the 'kcLoginAction' input value ...
#        "AUTH_SESSION_ID": ... the cookie value ...
#        "KC_RESTART": ... the cookie value ...
#    }
def resolveStandardUserTokenRequestParameters(clientId, logger, args):
    params = {}

    baseUrl = resolveKeycloakOpenidAccessUrl(args) + "/auth"
    locItems = urllib.parse.urlparse(baseUrl)
    ## By default, the quote function is intended for quoting the path
    ##  section of a URL.  Thus, it will not encode '/' - unless we override
    ## the 'safe' string
    redirectUri = urllib.parse.quote(locItems.scheme + "://" + locItems.netloc + "/", safe = '')
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

    rsp = executeHttpRequest(url, "GET", { "Accepts": "*/*" }, None, logger, args, asJson=False)
    params['loginUrl'] = extractKeycloakLoginActionValue(rsp['body'].split('\n'))

    cookies = rsp['cookies']
    params['AUTH_SESSION_ID'] = cookies.get("AUTH_SESSION_ID", None)
    params['KC_RESTART'] = cookies.get("KC_RESTART", None)

    return params

# Use the parameters retrieved from 'resolveStandardUserTokenRequestParameters':
#
# POST ... the 'kcLoginAction' value ...
#
# Headers:
#    Cookie(s): AUTH_SESSION_ID and KC_RESTART cookies
#    Content-Type: application/x-www-form-urlencoded
#    Referer: the 'referer' parameter from the previous request parameters
#
# Body:
#    username=...username...&password=...password...
#
# Until 200 OK is returned there should be a 302 (redirect) response
# whose 'Location' header contains a 'code' query parameter:
#
#    Location: ..../#state=...&code=....&....
#
# Return value:
#    {
#        "url": ... the url that was re-directed ...
#        "code": ... the extracted 'code' value from the re-direct location ...
#        "cookies": ... all cookies returned from the 200 (OK) response ...
#    }
def resolveKeycloakSessionAuthenticationCode(username, password, clientId, params, logger, args):
    url = params['loginUrl']
    if isEmpty(url):
        die("Failed to extract Keycloak login URL value")

    cookies = { }

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

    rsp = executeHttpRequest(url, "POST", requestHeaders, formData, logger, args, cookieJar=cookies, asJson=False)
    redirectHistory = rsp.get("history", None)
    if isEmpty(redirectHistory):
        die("No Keycloak redirection history available after successful authentication")

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

# Uses the code value retrieved from 'resolveStandardUserTokenRequestParameters':
#
#
# POST https://...host.../auth/realms/${realm:unifiedpush-installations}/protocol/openid-connect/token
#
# Headers:
#     Accepts: application/json
#     Content-Type": application/x-www-form-urlencoded
#
# Body:
#
#    grant_type=authorization_code&code=...the extracted code...&client_id=...the client id...&redirect_uri=...the same URI used in previous steps
#
# Return value: the Keycloak JSON containing the 'access_code' field
def resolveStandardUserToken(username, password, clientId, logger, args):
    params = resolveStandardUserTokenRequestParameters(clientId, logger, args)
    redirectUri = urllib.parse.unquote(params['redirectUri'])

    params = resolveKeycloakSessionAuthenticationCode(
        username, password, clientId, params, logger, args)

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

    url = resolveKeycloakDirectTokenAccessUrl(args)
    rsp = executeHttpRequest(url, "POST", requestHeaders, formData, logger, args, asJson=True)
    return rsp["body"]

# ----------------------------------------------------------------------------

def resolveUserToken(username, password, logger, args):
    logger.info("Retrieving Keycloak access token")

    if isinstance(username, (int, float)):
        username = str(username)
    elif isEmpty(username):
        die("No Keycloak access username provided")

    if isinstance(password, (int, float)):
        password = str(password)
    elif isEmpty(password):
        die("No Keycloak access password provided")

    clientId = args.get("clientId", None)

    if isEmpty(clientId):
        die("No Keycloak client identifier provided")

    clientIdFormat = args.get("clientIdFormat", "ups-installation-%s")
    effectiveClientId = clientIdFormat % clientId

    mode = args.get("mode", "STANDARD")
    mode = mode.upper()
    if mode == "STANDARD":
        rsp = resolveStandardUserToken(
            username, password, effectiveClientId, logger, args)
    elif mode == "DIRECT":
        rsp = resolveDirectGrantUserToken(
            username, password, effectiveClientId, logger, args)
    else:
        die("Unknown Keycloak access token retrieval mode: %s" % mode)

    accessToken = rsp.get("access_token", None)
    if isEmpty(accessToken):
        logger.error("No access token in Keycloak response: %s" % str(rsp))
        die("No access token returned from Keycloak")
    logger.info("Retrieved Keycloak access token")
    return accessToken


# ----------------------------------------------------------------------------

def resolveExportResponseReportAccessUrl(args):
    if args is None:
        die("No dashboard access arguments provided")

    protocol = args.get("protocol", "https")
    host = args.get("host", None)
    if isEmpty(host):
        die("No dashboard host specified")

    port = args.get("port", -1)
    endpoint = args.get("endpoint", "v1/report/exporter/response/report")
    if port > 0:
        return "%s://%s:%d/%s" % (protocol, host, port, endpoint)
    else:
        return "%s://%s/%s" % (protocol, host, endpoint)

def buildDashboardRetrievalFilter(stateValue):
    if stateValue == 'ALL':
        return None
    elif (stateValue == "OPENED") or (stateValue == "CLOSED"):
        return {
            "type": "term",
            "key": "state",
            "value": stateValue
        }
    else:
        die("Unknown state value requested: %s" % stateValue)

def exportResponseReportCsv(accessToken, accessParams, logger, args):
    url = resolveExportResponseReportAccessUrl(accessParams)
    request = { }
    page = {
        "from": 0,
        "size": args.get("limitRows", 99999999)
    }

    orders = [ { "direction": "ASC", "fieldName": "storeName" }, { "direction": "ASC", "fieldName": "productName" } ]

    request["page"] = page
    request["orders"] = orders


    reqData = json.dumps(request, indent=None, sort_keys=False)
    requestHeaders = {
        "Content-Type": "application/json",
        "Authorization": "Bearer %s" % accessToken,
        "Accept": "application/csv"
    }

    downloadReport(url, "POST", requestHeaders, reqData, logger, args);

def resolveOutputFilePath(args):
    filePath = args.get("file", None)
    if not isEmpty(filePath):
        filePath = resolvePathVariables(filePath)
        if os.path.isabs(filePath):
            return filePath

    dirPath = args.get("dir", None)
    if not isEmpty(dirPath):
        dirPath = resolvePathVariables(dirPath)

    if isEmpty(dirPath):
        if isEmpty(filePath):
            return None
        else:
            dirPath = os.getcwd()
    elif isEmpty(filePath):
        username = args.get("username", None)
        pos = username.find('@')    # Strip e-mail domain
        if pos > 0:
            username = username[0:pos]
        filePath = "%s-dashboard-responses.csv" % username

    if not os.path.isabs(dirPath):
        dirPath = os.path.abspath(dirPath)
    return os.path.join(dirPath, filePath)

# expected structure is:
# {
#      "closedTasks": 6,
#      "openedTasks": 103,
#      "storeName": "Dolphin FL Taubman",
#      "storeId": "2351067846609469440"
# }
def writeResultRow(fout, r, stateValue):
    storeName = r['storeName'].replace(',', '') # Avoid CSV parsing issues
    if (stateValue == 'ALL') or (stateValue == 'CLOSED'):
        fout.write("%s,%s,CLOSED,%d" % (r['storeId'], storeName, r['closedTasks']))
        fout.write('\n')

    if (stateValue == 'ALL') or (stateValue == 'OPENED'):
        fout.write("%s,%s,OPEN,%d" % (r['storeId'], storeName, r['openedTasks']))
        fout.write('\n')

# Results row format is "storeKey,storeName,state,count" - e.g. "1234,Hello world,OPEN,15"
def writeResultsToOutput(filePath, withHeaders, stateValue, rows, logger):
    numResults = len(rows)
    if numResults <= 0:
        logger.warning("No results returned")

    if isEmpty(filePath):
        print("===========================================================")
        if withHeaders:
            print("storeKey,storeName,state,count")
        for r in rows:
            writeResultRow(sys.stdout, r, stateValue)
        print("===========================================================")
    else:
        logger.info("Writing %d results to %s" % (numResults, filePath))

        with open(filePath, "w") as fout:
            if withHeaders:
                fout.write("storeKey,storeName,state,count")
                fout.write("\n")
            for r in rows:
                writeResultRow(fout, r, stateValue)

        logger.info("Written %d results to %s" % (numResults, filePath))

def dumpResults(username, accessToken, accessParams, outputParams, logger, args):
    stateValue = accessParams.get("state", "ALL")
    stateValue = stateValue.upper()

    exportResponseReportCsv(accessToken, accessParams, logger, args)
    return

# ----------------------------------------------------------------------------

# Adds the protocol/host/port if provided and not already set
def resolveEndpointAccessParameters(protocol, host, port, args):
    if not isEmpty(protocol):
        args = putIfAbsent(args, "protocol", protocol)
    if not isEmpty(host):
        args = putIfAbsent(args, "host", host)
    if port > 0:
        args = putIfAbsent(args, "port", port)
    return args

def doMain(args):
    logFactory = LogFactory(args)
    logger = logFactory.getLogger("main")
    configFile = args.get("configFile", None)
    if not isEmpty(configFile):
        logger.info("Using configuration file=%s" % configFile)

    protocol = args.get("protocol", "https")
    host = args.get("host", None)
    port = args.get("port", -1)

    accessToken = args.get("accessToken", None)
    username = args.get("username", None)
    if isinstance(accessToken, (int, float)):
        accessToken = str(accessToken)
    elif isEmpty(accessToken):
        accessParams = resolveEndpointAccessParameters(protocol, host, port, args)
        accessToken = resolveUserToken(
            username, args.get("password", None), logger, accessParams)

    print(accessToken)
    outputParams = args.get("output", {})
    dumpResults(username, accessToken, accessParams, outputParams, logger, args)

def main(args):
    if len(args) > 0:
        subArgs = parseCommandLineArguments(args)
    else:
        subArgs = {}

    configFile = subArgs.get("configFile", None)
    if not isEmpty(configFile):
        configFile = resolvePathVariables(configFile)
        if not os.path.isabs(configFile):
            dir = os.path.abspath(os.getcwd())
            configFile = os.path.join(dir, configFile)
            subArgs["configFile"] = configFile

        extraArgs = loadJsonFile(configFile)
        subArgs = mergeCommandLineArguments(subArgs, extraArgs)

    doMain(subArgs)
    sys.exit(0)

# ----------------------------------------------------------------------------

def signal_handler(signal, frame):
    die('Exit due to Control+C')

if __name__ == "__main__":
    pyVersion = sys.version_info
    if pyVersion.major != 3:
        die("Major Python version must be 3.x: %s" % str(pyVersion))
    if pyVersion.minor < 0:
        die("Minor Python version %s should be at least 3.0+" % str(pyVersion))

    signal.signal(signal.SIGINT, signal_handler)
    if os.name == 'nt':
        sys.stderr.write("Use Ctrl+Break to stop the script\n")
    else:
        sys.stderr.write("Use Ctrl+C to stop the script\n")
    main(sys.argv[1:])

