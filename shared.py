
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


class PipelineState(object):

    def __init__(self):
        self.score = 0
        self.issues = []

    def increase_score(self, val):
        self.score += val

    def add_issue(self, severity, desc, additional={}):
        self.issues.append(Issue(severity, desc, additional=additional))


class Pipeline(object):
    
    def __init__(self):
        self.plugins = []
        self.state = PipelineState()

    def add_plugin(self, plugin):
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

