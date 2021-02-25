import argparse
import datetime
from calendar import monthrange

from reports_exporter.report_type import ReportType
from reports_exporter.utils import die, isEmpty

DEFAULT_WEEKS_COUNT = 4
DEFAULT_LOG_THRESHOLD = "INFO"
DEFAULT_FIRST_DAY_OF_WEEK = "MON"
DEFAULT_DOMAIN="mcs.c-b4.com"

SHIFT_DAYS = {
    "SUN": 1,
    "MON": 0,
    "TUE": -1,
    "WED": -2,
    "THU": -3,
    "FRI": -4,
    "SAT": -5,
}


def shift_date_to_first_day_of_week(date, day_of_week):
    first_day = date - datetime.timedelta(days=(date.weekday() + SHIFT_DAYS[day_of_week]) % 7)
    return datetime.datetime.combine(first_day, datetime.time.min)


def shift_date_to_first_day_of_month(date: datetime):
    return date.replace(day=1)


def shift_date_to_end_day_of_week(date, day_of_week):
    end_day = shift_date_to_first_day_of_week(date, day_of_week) + datetime.timedelta(days=6)
    return datetime.datetime.combine(end_day, datetime.time.max)


def shift_date_to_end_day_of_month(date: datetime):
    return date.replace(day=monthrange(date.year, date.month)[1])


def parse_date(date_str, format="%Y-%m-%d", format_hint="yyyy-mm-dd"):
    try:
        return datetime.datetime.strptime(date_str, format)
    except:
        raise Exception("Invalid start_date: " + date_str + ". Format expected: " + format_hint)


def parse_site_url(args):
    url = args["site_basic_url"]

    protocol = url.split("://")[0]
    args["protocol"] = protocol

    base_url = url.split("://")[1]
    args["host"] = base_url.split(":")[0]
    if len(base_url.split(":")) > 1:
        args["port"] = base_url.split(":")[1]
    domain = args.get("domain")

    if domain not in base_url:
        die("domain %s is missing from site_basic_url %s" % (domain, url))
    client_id = base_url.split("-%s" % domain)[0]
    args["clientId"] = client_id


def manage_earnings_report_start_and_end_dates(args):
    req_start_date = args.get("start_date")
    day_of_week = args.get("first_day_of_week", DEFAULT_FIRST_DAY_OF_WEEK)

    today = datetime.datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    if not isEmpty(req_start_date):
        args["start_date"] = shift_date_to_first_day_of_week(parse_date(req_start_date), day_of_week)
    else:
        start_date = today - datetime.timedelta(weeks=5*12*4)
        args["start_date"] = shift_date_to_first_day_of_week(start_date, day_of_week)

    req_end_date = args.get("end_date")
    if not isEmpty(req_end_date):
        args["end_date"] = shift_date_to_end_day_of_week(parse_date(req_end_date), day_of_week)
    else:
        args["end_date"] = shift_date_to_end_day_of_week(today, day_of_week)

    attribute_start_month = args.get("attribute_start_month")
    if not isEmpty(attribute_start_month):
        args["attribute_start_month"] = shift_date_to_first_day_of_month(parse_date(attribute_start_month, "%b-%Y", "MMM-yyyy"))
    else:
        start_date = today - datetime.timedelta(weeks=5*12*4)
        args["attribute_start_month"] = shift_date_to_first_day_of_month(start_date)

    attribute_end_month = args.get("attribute_end_month")
    if not isEmpty(attribute_end_month):
        args["attribute_end_month"] = shift_date_to_end_day_of_month(parse_date(attribute_end_month, "%b-%Y", "MMM-yyyy"))
    else:
        args["attribute_end_month"] = shift_date_to_end_day_of_month(today)


def manage_response_report_start_and_end_dates(args):
    req_start_date = args.get("start_date")
    req_end_date = args.get("end_date")
    day_of_week = args.get("first_day_of_week", DEFAULT_FIRST_DAY_OF_WEEK)
    weeks_count = args.get("weeks_count", DEFAULT_WEEKS_COUNT)
    if isEmpty(req_end_date) and isEmpty(req_start_date):
        today = datetime.datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = shift_date_to_end_day_of_week(today, day_of_week)
        args["end_date"] = end_date
        args["start_date"] = shift_date_to_first_day_of_week(end_date - datetime.timedelta(weeks=weeks_count), day_of_week)
        return

    if not isEmpty(req_end_date) and not isEmpty(req_start_date):
        args["start_date"] = shift_date_to_first_day_of_week(parse_date(req_start_date), day_of_week)
        args["end_date"] = shift_date_to_end_day_of_week(parse_date(req_end_date), day_of_week)
        return

    if not isEmpty(req_start_date):
        start_date = shift_date_to_first_day_of_week(parse_date(req_start_date), day_of_week)
        args["start_date"] = start_date
        args["end_date"] = shift_date_to_end_day_of_week(start_date + datetime.timedelta(weeks=weeks_count), day_of_week)
        return

    if not isEmpty(req_end_date):
        end_date = shift_date_to_end_day_of_week(parse_date(req_end_date), day_of_week)
        args["end_date"] = end_date
        args["start_date"] = shift_date_to_first_day_of_week(end_date - datetime.timedelta(weeks=weeks_count), day_of_week)


def process_args(args, report_type):
    args["domain"] = args.get("domain", DEFAULT_DOMAIN)
    parse_site_url(args)
    args["log-threshold"] = args.get("log-threshold", DEFAULT_LOG_THRESHOLD)

    if report_type is ReportType.RESPONSE:
        manage_response_report_start_and_end_dates(args)
    else:
        manage_earnings_report_start_and_end_dates(args)


class ArgumentParser:

    def __init__(self, report_type) -> None:
        super().__init__()
        self.report_type = report_type
        if report_type is ReportType.RESPONSE:
            self.parser = self.response_report_parser()
        else:
            self.parser = self.earning_report_parser()

    def response_report_parser(self):
        parser = argparse.ArgumentParser(description='Dumps the responses to a CSV file', formatter_class=argparse.RawTextHelpFormatter)
        self.common_arguments(parser)
        parser.add_argument('--start_date',
                            type=str,
                            dest='start_date',
                            help='Example: 2020-01-01 (format: YYYY-MM-dd)'
                            )
        parser.add_argument('--end_date',
                            type=str,
                            dest='end_date',
                            help='Example: 2020-07-01 (format: YYYY-MM-dd)'
                            )
        parser.add_argument('--language',
                            type=str,
                            dest='language',
                            default="en-US",
                            help='reasons language. Example: en-US'
                            )
        parser.add_argument('--weeks_count',
                            type=int,
                            dest='weeks_count',
                            default=DEFAULT_WEEKS_COUNT,
                            help="""If START_DATE & END_DATE are not set -> timespan = (today - weeks_count, today).
If  only START_DATE -> timespan = (start_date, start_date + weeks_count).
If  only only END_DATE ->  timespan = (end_date - weeks_count, end_date).
If both START_DATE & END_DATE are set - WEEKS_COUNT is ignored. 
"""
                            )
        return parser

    def earning_report_parser(self):
        parser = argparse.ArgumentParser(description='Dumps monthly earnings to a CSV file', formatter_class=argparse.RawTextHelpFormatter)
        self.common_arguments(parser)
        parser.add_argument('--start_date',
                            type=str,
                            dest='start_date',
                            help='The earliest deployment week in the exported report. The format should be yyyy-MM-dd'
                            )
        parser.add_argument('--end_date',
                            type=str,
                            dest='end_date',
                            help='The latest deployment week in the exported report. The format should be yyyy-MM-dd'
                            )
        parser.add_argument('--attribute_start_month',
                            type=str,
                            dest='attribute_start_month',
                            help='The earliest month to include revenue that was attributed in the exported report. The format should be MMM-yyyy'
                            )
        parser.add_argument('--attribute_end_month',
                            type=str,
                            dest='attribute_end_month',
                            help='The latest date to include revenue that was attributed in the exported report. The format should be MMM-yyyy'
                            )
        return parser

    def common_arguments(self, parser):
        parser.add_argument('--username',
                            type=str,
                            dest='username',
                            help='login username'
                            )
        parser.add_argument('--password',
                            type=str,
                            dest='password'
                            )
        parser.add_argument('--dir',
                            type=str,
                            dest='dir',
                            help='The CSVs directory path to dump the response report CSV (the default location is the script current directory)'
                            )
        parser.add_argument('--file',
                            type=str,
                            dest='file',
                            help='The CSVs directory path to dump the response report CSV (can be relative to dir or absolute path)'
                            )
        parser.add_argument('--site_basic_url',
                            type=str,
                            dest='site_basic_url',
                            help='Client url, example: https://someClient-mcs.com'
                            )
        parser.add_argument('--limitRows',
                            type=int,
                            dest='limitRows',
                            help='Limit the numbers of rows to export'
                            )
        parser.add_argument('--log-threshold',
                            type=str,
                            dest='log-threshold',
                            default=DEFAULT_LOG_THRESHOLD,
                            help="OFF, ERROR, WARNING, INFO, DEBUG, TRACE, ALL"
                            )
        parser.add_argument('--domain',
                            type=str,
                            dest='domain',
                            default=DEFAULT_DOMAIN,
                            help="domain name. default value %s" % DEFAULT_DOMAIN
                            )
        parser.add_argument('--first_day_of_week',
                            type=str,
                            dest='first_day_of_week',
                            default=DEFAULT_FIRST_DAY_OF_WEEK,
                            help='options: [SUN MON TUE WED THU FRI SAT] , default: MON'
                            )

    def parse_arguments(self):
        args = self.parser.parse_args()
        args = vars(args)
        for arg in args:
            if isEmpty(arg):
                args.pop(arg, None)
        process_args(args, self.report_type)
        return args
