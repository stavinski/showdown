
from datetime import datetime 
from shared import AbstractPlugin

class Plugin(AbstractPlugin):

    def process(self, host, output):
        if host['os']:
            output.add_info({ 
                'id': 'os_id',
                'description': f"OS: {host['os']}"
            })

        last_updated = datetime.strptime(host['last_update'], '%Y-%m-%dT%H:%M:%S.%f')
        output.add_info({
            'id': 'last_updated',
            'description': f"Last Updated: {last_updated:%Y-%m-%d %H:%M}"
        })

    @property
    def summary(self):
        return 'Standard information about the host'