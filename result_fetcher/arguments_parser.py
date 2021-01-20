import argparse
from tempfile import gettempdir

def isEmpty(s):
    if (s is None) or (len(s) <= 0):
        return True
    else:
        return False


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

        args = parser.parse_args()
        args = vars(args)
        for arg in args:
            if isEmpty(arg):
                args.pop(arg, None)
        parse_site_url(args)
        return args
