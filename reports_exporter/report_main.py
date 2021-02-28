#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os
import signal
import sys

from reports_exporter import access_token_fetcher
from reports_exporter import arguments_parser
from reports_exporter.custom_logging import LogFactory
from reports_exporter.earnings_report_fetcher import ReportFetcher as EarningsReportFetcher
from reports_exporter.report_type import ReportType
from reports_exporter.response_report_fetcher import ReportFetcher as ResponseReportFetcher
from reports_exporter.utils import isEmpty, die


class ResultFetcher:

    def __init__(self, report_type=ReportType.RESPONSE) -> None:
        super().__init__()
        self.report_type = report_type

    def signal_handler(self):
        die('Exit due to Control+C')

    def run(self, opt_args=None):
        pyVersion = sys.version_info
        if pyVersion.major != 3:
            die("Major Python version must be 3.x: %s" % str(pyVersion))
        if pyVersion.minor < 0:
            die("Minor Python version %s should be at least 3.0+" % str(pyVersion))

        signal.signal(signal.SIGINT, self.signal_handler)
        if os.name == 'nt':
            sys.stderr.write("Use Ctrl+Break to stop the script\n")
        else:
            sys.stderr.write("Use Ctrl+C to stop the script\n")

        if opt_args is None:
            args = arguments_parser.ArgumentParser(self.report_type).parse_arguments()
        else:
            args = opt_args
            arguments_parser.process_args(args, self.report_type)

        logFactory = LogFactory(args)
        logger = logFactory.getLogger("main")
        token_fetcher = access_token_fetcher.AccessTokenFetcher(logger, args)
        token = token_fetcher.get_access_token()
        if isEmpty(token):
            die("Could not get access token for the username")

        try:
            if self.report_type == ReportType.RESPONSE:
                self.response_report(args, logger, token)
            else:
                self.earnings_report(args, logger, token)
        finally:
            token_fetcher.logout(token)

    def response_report(self, args, logger, token):
        exporter = ResponseReportFetcher(logger, args)
        logger.info("Started exporting report, this may take a few minutes")
        exporter.export_report(token)

    def earnings_report(self, args, logger, token):
        exporter = EarningsReportFetcher(logger, args)
        logger.info("Started exporting report, this may take a few minutes")
        exporter.export_report(token)
