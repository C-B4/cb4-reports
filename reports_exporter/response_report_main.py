from reports_exporter import report_main
from reports_exporter.report_type import ReportType

# This file is for maintaining backwards compatibility from version 1.0.4 to version 2.0.1
# Please try to avoid it

class ResultFetcher:

    def response_report_main (self):
        return report_main.ResultFetcher(self, ReportType.RESPONSE)

    def run(self, opt_args =None):
        result_fetcher = report_main.ResultFetcher(ReportType.RESPONSE)
        result_fetcher.run(opt_args)
