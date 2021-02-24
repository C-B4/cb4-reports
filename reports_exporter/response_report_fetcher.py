#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

from reports_exporter.report_fetcher_base import ReportFetcherBase


class ReportFetcher(ReportFetcherBase):
    def __init__(self, logger, args) -> None:
        super().__init__(logger, args, "response_report")

    def export_report(self, access_token):
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
        orders = [
            {"direction": "ASC", "fieldName": "deployDate"},
            {"direction": "ASC", "fieldName": "storeName"},
            {"direction": "ASC", "fieldName": "productName"}
        ]
        if not self.args.get("limitRows") is None:
            return {
                "orders": orders,
                "page": {
                    "from": 0,
                    "size": self.args.get("limitRows")
                }
            }

        return {
            "orders": orders
        }

    def prepare_report_url(self, site_basic_url):
        report_url = "%s/%s" % (site_basic_url, "v1/report/exporter/response/report")
        return report_url
