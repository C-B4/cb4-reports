# response-report
Used for CB4 response report export API

## Instalation:
### Setup python3 and pip
```
sudo apt update
sudo apt install python3-pip

pip3 --version
```

### Alternative A
<ins>Step 1</ins>: Clone the repository from Github  
<ins>Step 2</ins>: Get credentials for the script  
<ins>Step 3</ins>: Go to the folder where the Github repository was cloned  
<ins>Step 4</ins>: Execute the script using your own credentials:  
```
python3 dump_results.py --username=your_username --site_base_url=yourClientId-cb4_host --limitRows=300 --dir=/path/to/directory_to_dump_the_results
```

### Alternative B
<ins>Step 1</ins>: Install the package from Github, using pip  
*Example*:
```
pip3 install git+ssh://git@github.com/C-B4/response-report.git@feature-transform-package

```
<ins>Step 2</ins>: Use the class in your scripts, as you wish  
*Example*:
```
import result_fetcher

result_fetcher = result_fetcher.ResultFetcher()
options = {
    "username": "your_username",
    "site_basic_url": "yourClientId-cb4_host",
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
