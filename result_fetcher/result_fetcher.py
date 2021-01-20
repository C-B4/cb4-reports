#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
import signal
import os

from result_fetcher.report_fetcher import ReportFetcher
from result_fetcher import arguments_parser
from result_fetcher import access_token_fetcher
from result_fetcher.custom_logging import LogFactory


def isEmpty(s):
    if (s is None) or (len(s) <= 0):
        return True
    else:
        return False


def die(msg=None,rc=1):
        """
        Cleanly exits the program with an error message
        """

        if msg:
            sys.stderr.write(msg)
            sys.stderr.write("\n")
            sys.stderr.flush()

        sys.exit(rc)


class ResultFetcher:
    def die(self, msg=None, rc=1):
        """
        Cleanly exits the program with an error message
        """

        if msg:
            sys.stderr.write(msg)
            sys.stderr.write("\n")
            sys.stderr.flush()

        sys.exit(rc)

    def signal_handler(self):
        self.die('Exit due to Control+C')

    def run(self, opt_args=None):
        pyVersion = sys.version_info
        if pyVersion.major != 3:
            self.die("Major Python version must be 3.x: %s" % str(pyVersion))
        if pyVersion.minor < 0:
            self.die("Minor Python version %s should be at least 3.0+" % str(pyVersion))

        signal.signal(signal.SIGINT, self.signal_handler)
        if os.name == 'nt':
            sys.stderr.write("Use Ctrl+Break to stop the script\n")
        else:
            sys.stderr.write("Use Ctrl+C to stop the script\n")

        if opt_args is None:
            argParser = arguments_parser.ArgumentParser()
            args = argParser.parse_arguments()
        else:
            args = opt_args
            arguments_parser.parse_site_url(args)
        self.main(args)

    def main(self, args):
        logFactory = LogFactory(args)
        logger = logFactory.getLogger("main")
        token_fetcher = access_token_fetcher.AccessTokenFetcher(logger, args)
        token = token_fetcher.get_access_token()
        if isEmpty(token):
            die("Could not get access token for the username")
        exporter = ReportFetcher(logger, args)
        exporter.export_response_report(token)

        sys.exit(0)
