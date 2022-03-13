
from shared import AbstractPlugin, Severity

class Plugin(AbstractPlugin):

    def process(self, host, state):
        if host['os']:
            state.add_issue(Severity.INFO, f"OS: {host['os']}")

        state.add_issue(Severity.INFO, f"Last Updated: {host['last_update']}")

    @property
    def summary(self):
        return 'Standard information about the host'