from shodan import Shodan, APIError

class ShodanAPI(object):
    
    def __init__(self, api_key):
        self.api = Shodan(api_key)

    def test(self):
        try:
            return True, self.api.info()
        except APIError as e:
            return False, e

    def host(self, ip):
        try:
            return True, ip, self.api.host(ip)
        except APIError as e:
            return False, ip, e