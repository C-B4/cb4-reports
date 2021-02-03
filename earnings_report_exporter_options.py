#!/usr/bin/env python
# -*- coding: utf-8 -*-

from reports_exporter import report_main, ReportType

result_fetcher = report_main.ResultFetcher(report_type=ReportType.EARNINGS)
options = {
    "username": "username",
    "site_basic_url": "https://sitename.c-b4.com",
    "limitRows": 300,
    "start_date": '2020-09-01',
    "end_date": '2021-03-11',
    "attribute_start_month": "Jan-2021",
    "attribute_end_month": "Apr-2021",
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
    - attribute_start_month
    - attribute_end_month
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
