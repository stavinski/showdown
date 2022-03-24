
from abc import ABCMeta, abstractmethod, abstractproperty
from enum import Enum
from functools import total_ordering


class Severity(Enum):
    INFO = 1
    LOW = 3
    MEDIUM = 5
    HIGH = 7
    CRITICAL = 10

    @classmethod
    def all(cls):
        return [
            cls.CRITICAL,
            cls.HIGH,
            cls.MEDIUM,
            cls.LOW,
            cls.INFO
        ]
    
    @classmethod
    def from_name(cls, name):
        found = [severity for severity in cls.all() if severity.name == name] 
        if not found:
            raise ValueError(f"{name} is not a valid Severity name.")
        
        return found[0]


class Finding(object):
    
    def __init__(self, id, value, summary, port='', severity=Severity.INFO, protocol='', references=[], items=[]):
        self.id = id
        self.value = value
        self.summary = summary
        self.port = port
        self.severity = severity
        self.protocol = protocol
        self.references = references
        self.items = items

    @property
    def has_port(self):
        return self.port != ''
    
@total_ordering
class OutputHost(object):

    def __init__(self) -> None:
        self._score = 0
        self._findings = []

    def add_finding(self, finding):
        self._findings.append(finding)

    def increase_score(self, val):
        if val < 0:
            raise ValueError('val can only be a positive value.')

        self._score += val

    def __eq__(self, other):
        return self.score == other.score

    def __lt__(self, other):
        return self.score < other.score

    @property
    def score(self):
        return int(self._score)

    @property
    def findings(self):
        return self._findings


class Pipeline(object):
    
    def __init__(self):
        self.plugins = []
        self.output = {}

    def register(self, plugin):
        self.plugins.append(plugin)

    def execute(self, host):
        # give the plugin a Host object to work against
        output = OutputHost()

        for plugin in self.plugins:
            plugin.process(host, output)
        
        # now store the host output against the ip
        self.output[host['ip_str']] = output

        # sort by the host descending (i.e. by score)
        sorted_by_host = {k: v for k, v in sorted(self.output.items(), key=lambda item: item[1], reverse=True)}
        return sorted_by_host


class AbstractPlugin(metaclass=ABCMeta):

    @abstractmethod
    def process(self, host, output):
        raise NotImplementedError()

    @abstractproperty
    def summary(self):
        raise NotImplementedError()


class AbstractFormatter(metaclass=ABCMeta):
    
    @abstractmethod
    def format(self, ip, host):
        raise NotImplementedError()

    def __enter__(self):
        self.begin()

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.end()

    def begin(self):
        pass

    def end(self):
        pass
