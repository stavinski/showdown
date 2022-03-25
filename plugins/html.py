
from shared import AbstractPlugin


class Plugin(AbstractPlugin):
    
    def process(self, host, output):
        pass

    @property
    def summary(self):
        return 'Checks html services to try and discover interesting findings such as logins.'
