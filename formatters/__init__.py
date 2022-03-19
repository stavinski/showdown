from contextlib import contextmanager
from .csvformatter import CSVFormatter
from .consoleformatter import ConsoleFormatter


class FormattersRegistry(object):

    available = ['console', 'csv']

    def __init__(self, args):
        self.registered = {
            'console': ConsoleFormatter(args),
            'csv': CSVFormatter(args)
        }
    
    def get(self, name):
        if name not in self.registered:
            raise ValueError(f"{name} is not a registered formatter.")
        
        return self.registered[name]