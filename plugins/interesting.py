
from shared import AbstractPlugin


class Plugin(AbstractPlugin):
    
    def process(self, host, output):
        pass

    @property
    def summary(self):
        return 'Checks for interesting ports available.'

