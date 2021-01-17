import result_fetcher

result_fetcher = result_fetcher.ResultFetcher()
options = {
    "username": "noam@grr.la",
    "password": "1",
    "host": "qa2-staging-mcs.c-b4.com",
    "clientId": "qa2",
    "limitRows": 300,
    "dir": "~/data/LSD/projects/response-report/"
}

"""
Available keys for the options dictionary:
    - log-datetime
    - protocol
    - log-stacktrace
    - log-auto
    - log-console
    - connectTimeout
    - responseTimeout
    - realm
    - clientId
    - clientIdFormat
    - mode
    - host
    - port
    - endpoint
    - limitRows
    - file
    - dir
    - accessToken
    - username
    - password
    - output
    - configFile
"""

result_fetcher.run(options)
