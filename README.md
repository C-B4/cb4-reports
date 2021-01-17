# response-report
Used for CB4 response report export API

## Instalation:
### Alternative A
Step 1: Clone the reposiotry from Github
Step 2: Get credentials for the script
Step 3: Go to the folder where the Github repository was cloned
Step 4: Execute the script using your own credentials:
```
python3 dump_results.py --username=your_username --password=your_password --host=cb4_host --clientId=valid_client_id --limitRows=300 --dir=/path/to/directory_to_dump_the_results
```

### Alternative B
Step 1: Install the package from Github, using pip
Example:
```
pip3 install git+https://github.com/
```
Step 2: Use the class in your scripts, as you wish
Example:
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
