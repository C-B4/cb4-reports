from reports_exporter import report_main
from reports_exporter.report_type import ReportType


class ResultFetcher:

    def response_report_main (self):
        return report_main.ResultFetcher(self, ReportType.RESPONSE)

    def run(self, opt_args =None):
        result_fetcher = report_main.ResultFetcher(ReportType.RESPONSE)
        result_fetcher.run(opt_args)
