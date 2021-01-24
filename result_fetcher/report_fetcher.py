#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import requests
import urllib
import urllib.error
import urllib.request
import os
from tempfile import gettempdir


def isEmpty(s):
    if (s is None) or (len(s) <= 0):
        return True
    else:
        return False


class ReportFetcher:
    def __init__(self, logger, args) -> None:
        super().__init__()
        self.logger = logger
        self.args = args

    def export_response_report(self, access_token):
        report_url, reqData, requestHeaders = self.prepare_request(access_token)
        self.downloadReport(report_url, "POST", requestHeaders, reqData)

    def prepare_request(self, access_token):
        site_basic_url = self.args.get("site_basic_url")
        report_url = self.prepare_report_url(site_basic_url)

        request = self.prepare_request_page_and_order()
        request = self.prepare_request_dates(request)
        request = self.prepare_request_language(request)

        reqData = json.dumps(request, indent=None, sort_keys=False)

        requestHeaders = {
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % access_token,
            "Accept": "application/csv"
        }
        return report_url, reqData, requestHeaders

    def prepare_request_language(self, request):
        request["reasonLang"] = self.args.get("language", "en-US")
        return request

    def prepare_request_dates(self, request):
        request["filter"] = {
            "from": int(self.args.get("start_date").timestamp() * 1000),
            "key": "deployDate",
            "to": int(self.args.get("end_date").timestamp() * 1000),
            "type": "time"
        }
        return request

    def prepare_request_page_and_order(self):
        page = {
            "from": 0,
            "size": self.args.get("limitRows", 99999999)
        }
        orders = [{"direction": "ASC", "fieldName": "storeName"}, {"direction": "ASC", "fieldName": "productName"}]
        request = {
            "page": page,
            "orders": orders
        }
        return request

    def prepare_report_url(self, site_basic_url):
        report_url = "%s/%s" % (site_basic_url, "v1/report/exporter/response/report")
        return report_url

    def downloadReport(self, url, verb, headersMap, reqData):
        if headersMap is None:
            headersMap = {}

        dataBytes = None
        if not isEmpty(reqData):
            dataBytes = bytes(reqData, 'utf-8')
            headersMap["Content-Length"] = str(len(dataBytes))

        try:
            # InsecureRequestWarning: Unverified HTTPS request is being made.
            requests.packages.urllib3.disable_warnings()

            self.logger.info("%s %s" % (verb, url))
            connTimeout = self.args.get("connectTimeout", 15)
            rspTimeout = self.args.get("responseTimeout", 3000)
            rsp = requests.request(verb, url, headers=headersMap,
                data=dataBytes, verify=False, timeout=(connTimeout, rspTimeout))
            statusCode = rsp.status_code
            if (statusCode < 200) or (statusCode >= 400):
                raise urllib.error.HTTPError(url, statusCode, "Failed: %d" % statusCode, rsp.headers, None)

            filePath = self.resolveOutputFilePath()
            text_file = open(filePath, "wb")
            for chunk in rsp.iter_content(chunk_size=1024):
                text_file.write(chunk)

            text_file.close()
        except urllib.error.HTTPError as err:
            self.logger.error("Failed (%d %s) to invoke %s %s" % (err.code, err.msg, verb, url))
            raise err
        except urllib.error.URLError as err:
            self.logger.error("Some unknown error for %s %s: %s" % (verb, url, err.reason))
            raise err

    def resolveOutputFilePath(self):
        filePath = self.args.get("file", None)
        if not isEmpty(filePath):
            filePath = self.resolvePathVariables(filePath)
            if os.path.isabs(filePath):
                print("Writing report to: {}".format(filePath))
                return filePath

        dirPath = self.args.get("dir", None)
        if not isEmpty(dirPath):
            dirPath = self.resolvePathVariables(dirPath)
        else:
            dirPath = gettempdir()


        if isEmpty(filePath):
            username = self.args.get("username", None)
            pos = username.find('@')    # Strip e-mail domain
            if pos > 0:
                username = username[0:pos]
            filePath = "%s-dashboard-responses.csv" % username

        if not os.path.isabs(dirPath):
            dirPath = os.path.abspath(dirPath)

        path = os.path.join(dirPath, filePath)
        print("Writing report to: {}".format(path))
        return path

    def resolvePathVariables(self, path):
        """
        Expands ~/xxx and ${XXX} variables
        """
        if isEmpty(path):
            return path

        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
        return path
