from .csvformatter import CSVFormatter
from .consoleformatter import ConsoleFormatter

class FormattersRegistry(object):

    available = ['console', 'csv']

    def __init__(self) -> None:
        self.registered = {
            'console': ConsoleFormatter(),
            'csv': CSVFormatter()
        }
    
    def get(self, name):
        if name not in self.registered:
            raise ValueError(f"{name} is not a registered formatter.")

        return self.registered[name]