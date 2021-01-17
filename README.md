# response-report
Used for CB4 response report export API

## Instalation:
### Alternative A
<ins>Step 1</ins>: Clone the repository from Github  
<ins>Step 2</ins>: Get credentials for the script  
<ins>Step 3</ins>: Go to the folder where the Github repository was cloned  
<ins>Step 4</ins>: Execute the script using your own credentials:  
```
python3 dump_results.py --username=your_username --password=your_password --host=cb4_host --clientId=valid_client_id --limitRows=300 --dir=/path/to/directory_to_dump_the_results
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
    "password": "your_password",
    "host": "cb4_host",
    "clientId": "valid_client_id",
    "limitRows": 300,
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
    - host
    - port
    - endpoint
    - limitRows
    - file
    - dir
    - accessToken
    - username
    - password
    - output
    - configFile
"""
result_fetcher.run(options)

```
