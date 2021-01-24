# CB4 Reports
Export reports from CB4 application

## Installation
Available Installation options described in this readme are installing the reports as a package and cloning the repository.
Follow option A to install as a package or option B to clone the repository
### Requirements
- Python 3
- CB4 application credentials

### Option A - Use as Package
Install the package from Github, using pip
```bash
python3 -m pip install git+ssh://git@github.com/C-B4/cb4-reports.git@main
```
Install required python packages
```bash
python3 -m pip install -r requirements.txt
```
import and use the class in your scripts in your code

Example:
```python
import result_fetcher

result_fetcher = result_fetcher.ResultFetcher()
options = {
    "username": "username",
    "site_basic_url": "https://sitename.c-b4.com",
    "limitRows": 300,
    "start_date": '2020-01-01',
    "end_date": '2022-07-01',
    "dir": "/path/to/directory_to_dump_the_results"
}

"""
Available keys for the options dictionary:
    - log-datetime
    - protocol
    - log-stacktrace
    - log-auto
    - log-console
    - connectTimeout
    - responseTimeout
    - realm
    - clientId
    - clientIdFormat
    - mode
    - endpoint
    - limitRows
    - file
    - dir
    - accessToken
    - username
    - output
    - configFile
    - start_date
    - end_date
    - language
    - site_basic_url
"""
result_fetcher.run(options)

```

### Option 2 - Clone Repository

Clone the response-report repository from Github

```git clone https://github.com/C-B4/cb4-reports.git```

Install required packages from the cloned directory
```
python3 -m pip install -r requirements.txt
```

Execute Script with --help for detailed execution instructions
```
python3 dump_results.py --help
```

Script execution example
```
python3 dump_results.py --username=user@cb4.com --site_basic_url=https://sitename.c-b4.com --dir=<Export Path> --limitRows=<Max Rows>
```