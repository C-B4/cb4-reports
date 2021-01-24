#!/usr/bin/env python
# -*- coding: utf-8 -*-

from reports_exporter import response_report_main

result_fetcher = response_report_main.ResultFetcher()
options = {
    "username": "username",
    "site_basic_url": "https://sitename.c-b4.com",
    "limitRows": 300,
    "start_date": '2020-01-01',
    "end_date": '2021-01-11',
    #"log-threshold": "DEBUG"
    "dir": "/tmp"
}

"""
Available keys for the options dictionary:
    - site_basic_url
    - dir
    - file
    - username
    - start_date
    - end_date
    - language
    - log-datetime
    - log-threshold
    - connectTimeout
    - responseTimeout
    - realm
    - clientIdFormat
    - mode
    - limitRows
    - accessToken
"""

result_fetcher.run(options)
