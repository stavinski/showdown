
from datetime import datetime 
from shared import AbstractPlugin, Finding

class Plugin(AbstractPlugin):

    def process(self, host, output):
        if host['os']:
            output.add_finding(Finding('os_id', host['os'], f"OS: {host['os']}"))

        last_updated = datetime.strptime(host['last_update'], '%Y-%m-%dT%H:%M:%S.%f')
        output.add_finding(Finding('last_updated', last_updated, f"Last Updated: {last_updated:%Y-%m-%d %H:%M}"))

    @property
    def summary(self):
        return 'Standard information about the host'