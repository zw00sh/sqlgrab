```bash
usage: sqlgrab.py [-h] -u HOST -r REQUEST -q QUERY -d {mysql,mssql,oracle,postgresql} -c CONDITION [--delay DELAY] [--urlencode] [--proxy PROXY]

Extracts string data from a conditional SQLi vulnerability using a binary search tree approach.

options:
  -h, --help            show this help message and exit
  -u HOST, --host HOST  Host URL, including protocol scheme and optionally port. E.g. https://target.com:80
  -r REQUEST, --request REQUEST
                        Request file containing one or more '{payload}' tags
  -q QUERY, --query QUERY
                        SQL query to extract the response of. Must return a single string, e.g. @@version, SELECT user FROM dual
  -d {mysql,mssql,oracle,postgresql}, --dbms {mysql,mssql,oracle,postgresql}
  -c CONDITION, --condition CONDITION
                        Python expression to evaluate to determine true/false from the response. E.g. '"error" in response.text', 'response.status_code == 401', 'len(response.content) > 1433'
  --delay DELAY         Delay in seconds to add between requests. Optional. E.g. 1, 0.2
  --urlencode           Perform URL-encoding on the payloads. Optional. E.g. True, False
  --proxy PROXY         Proxy to use, e.g. http://127.0.0.1:8080
  ```