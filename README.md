# cb4-reports
Export reports from CB4 application.
Available Reports: 
- Response Report
- Earnings Report

## Installation
Available installation options described in this readme are installing the reports as a package and cloning the repository.
Follow option A to install as a package or option B to clone the repository
### Requirements
- Python 3
- CB4 application credentials

### Option A - Use as Package
Install the package from Github, using pip
```bash
python3 -m pip install cb4-reports-exporter
```
Install required python packages
```bash
python3 -m pip install -r requirements.txt
```
import and use the class in your scripts in your code

Response Report Example:

```python
from reports_exporter import report_main

result_fetcher = report_main.ResultFetcher()
options = {
    "username": "username",
    "password": "password",
    "site_basic_url": "https://sitename.c-b4.com",
    "limitRows": 300,
    "start_date": '2020-01-01',
    "end_date": '2021-01-11',
    # "log-threshold": "DEBUG"
    "dir": "/tmp"
}

"""
Available keys for the options dictionary:
    - site_basic_url
    - dir
    - file
    - username
    - password
    - start_date
    - end_date
    - language
    - log-datetime
    - log-threshold
    - connectTimeout
    - responseTimeout
    - realm
    - clientIdFormat
    - mode
    - limitRows
    - accessToken
"""

result_fetcher.run(options)
```
Earning Report Example:
```python
from reports_exporter import report_main, ReportType

result_fetcher = report_main.ResultFetcher(report_type=ReportType.EARNINGS)
options = {
    "username": "username",
    "site_basic_url": "https://sitename.c-b4.com",
    "limitRows": 300,
    "start_date": '2020-09-01',
    "end_date": '2021-03-11',
    "attribute_start_month": "Jan-2021",
    "attribute_end_month": "Apr-2021",
    #"log-threshold": "DEBUG"
    "dir": "/tmp"
}

"""
Available keys for the options dictionary:
    - site_basic_url
    - dir
    - file
    - username
    - start_date
    - end_date
    - attribute_start_month
    - attribute_end_month
    - log-datetime
    - log-threshold
    - connectTimeout
    - responseTimeout
    - realm
    - clientIdFormat
    - mode
    - limitRows
    - accessToken
"""
result_fetcher.run(options)
```

### Option 2 - Clone Repository

Clone cb4-reports repository from Github

```git clone https://github.com/C-B4/cb4-reports.git```

Install required packages from the cloned directory
```
python3 -m pip install -r requirements.txt
```

Execute Script with --help for detailed execution instructions
```
python3 script_name.py --help
```
Examples:
```
python3 response_report_exporter.py --help
python3 earnings_report_exporter.py --help
```

Script execution example
```
python3 response_report_exporter.py --username=<cb4 user name> --password=<cb4 user password> --site_basic_url=https://sitename.c-b4.com --dir=<Export Path> --end_date=2020-01-01 --limitRows=<Max Rows>
python3 earnings_report_exporter.py --username=<cb4 user name> --password=<cb4 user password> --site_basic_url=https://sitename.c-b4.com --dir=<Export Path> --end_date=2020-01-01 --limitRows=<Max Rows>
```