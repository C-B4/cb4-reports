#!/usr/bin/env python
# -*- coding: utf-8 -*-

from reports_exporter import report_main
from reports_exporter.report_type import ReportType

result_fetcher = report_main.ResultFetcher(report_type=ReportType.EARNINGS)
result_fetcher.run()
