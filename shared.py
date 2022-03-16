
from abc import abstractmethod, abstractproperty
from enum import Enum

class Issue(object):
    
    def __init__(self, severity, desc, additional={}):
        self.severity = severity
        self.desc = desc
        self.additional = additional


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


class Host(object):
    def __init__(self):
        self.score = 0
        self.issues = []


class PipelineState(object):

    def __init__(self):
        self.hosts = {}

    def increase_score(self, host, val):
        host = self._get_or_create(host)
        host.score += val

    def add_issue(self, host, severity, desc, additional={}):
        host = self._get_or_create(host)
        host.issues.append(Issue(severity, desc, additional=additional))

    def _get_or_create(self, host):
        ip = host['ip_str']
        if ip in self.hosts:
            return self.hosts[ip]
        
        self.hosts[ip] = Host()
        return self.hosts[ip]


class Pipeline(object):
    
    def __init__(self):
        self.plugins = []
        self.state = PipelineState()

    def register(self, plugin):
        self.plugins.append(plugin)

    def execute(self, host):
        for plugin in self.plugins:
            plugin.process(host, self.state)
        
        return self.state


class AbstractPlugin(object):

    @abstractmethod
    def process(self, host, state):
        raise NotImplementedError()

    @abstractproperty
    def summary(self):
        raise NotImplementedError()

