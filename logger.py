
from enum import Enum


class LogLevel(Enum):
    INFO = 0
    DEBUG = 1
    VERBOSE =2
    SPAM = 3


class Log(object):

    def __init__(self, level):
        self.level = level

    def write(self, val, level=LogLevel.INFO, end=None, flush=None):
        if self.level >= level.value:
            print(val, end=end, flush=flush)