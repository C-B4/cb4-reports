#!/usr/bin/env python
# -*- coding: utf-8 -*-

import result_fetcher

result_fetcher = result_fetcher.ResultFetcher()
options = {
    "username": "noam@grr.la",
    "site_basic_url": "https://qa2-staging-mcs.c-b4.com",
    "limitRows": 300,
    "start_date": '2020-01-01',
    "end_date": '2022-07-01',
    "dir": "/tmp/"
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
    - endpoint
    - limitRows
    - file
    - dir
    - accessToken
    - username
    - output
    - configFile
    - start_date
    - end_date
    - language
    - site_basic_url
"""

result_fetcher.run(options)
