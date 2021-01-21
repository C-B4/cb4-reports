import argparse
import datetime

DEFAULT_FIRST_DAY_OF_WEEK = "MON"

DEFAULT_FIRST_DAY_OF_WEEK = "MON"

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


def shift_date_to_end_day_of_week(date, day_of_week):
    end_day = shift_date_to_first_day_of_week(date, day_of_week) + datetime.timedelta(days=6)
    return datetime.datetime.combine(end_day, datetime.time.max)


def isEmpty(s):
    if (s is None) or (len(s) <= 0):
        return True
    else:
        return False


def parse_date(date_str):
    try:
        return datetime.datetime.strptime(date_str, "%Y-%m-%d")
    except:
        raise Exception("Invalid start_date. Format expected: yyyy-mm-dd")


def parse_site_url(args):
    url = args["site_basic_url"]

    protocol = url.split("://")[0]
    args["protocol"] = protocol

    base_url = url.split("://")[1]
    args["host"] = base_url.split(":")[0]
    if len(base_url.split(":")) > 1:
        args["port"] = base_url.split(":")[1]

    sub_domain = base_url.split(".")[0]
    client_id = sub_domain.split("-")[0]
    args["clientId"] = client_id


def manage_start_and_end_dates(args):
    req_start_date = args.get("start_date")
    day_of_week = args.get("first_day_of_week")
    if not isEmpty(req_start_date):
        args["start_date"] = shift_date_to_first_day_of_week(parse_date(req_start_date), day_of_week)
    else:
        today = datetime.datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        first_day_of_week = shift_date_to_first_day_of_week(today, day_of_week)
        args["start_date"] = first_day_of_week - datetime.timedelta(weeks=4)

    req_end_date = args.get("end_date")
    if not isEmpty(req_end_date):
        args["end_date"] = shift_date_to_end_day_of_week(parse_date(req_end_date), day_of_week)
    else:
        today = datetime.datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        args["end_date"] = shift_date_to_end_day_of_week(today, day_of_week)


def process_args(args):
    parse_site_url(args)
    manage_start_and_end_dates(args)


class ArgumentParser:

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='Dumps the responses to a CSV file')
        parser.add_argument('--username',
                            type=str,
                            dest='username',
                            help='login username'
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
        parser.add_argument('--first_day_of_week',
                            type=str,
                            dest='first_day_of_week',
                            default=DEFAULT_FIRST_DAY_OF_WEEK,
                            help='options: [SUN MON TUE WED THU FRI SAT] , default: MON'
                            )

        args = parser.parse_args()
        args = vars(args)
        for arg in args:
            if isEmpty(arg):
                args.pop(arg, None)
        process_args(args)
        return args
