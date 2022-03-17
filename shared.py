
from abc import abstractmethod, abstractproperty
from enum import Enum
from multiprocessing import set_forkserver_preload

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

class Finding(object):
    
    def __init__(self, severity, desc, additional={}):
        self.severity = severity
        self.desc = desc
        self.additional = additional


class Host(object):
    def __init__(self):
        self.score = 0
        self.issues = []


class PipelineHostOutput(object):

    def __init__(self):
        self.host = { 'score': 0, 'findings': [], 'infos': [] }

    def increase_score(self, val):
        self.host['score'] += val

    def add_info(self, info):
        self.host['infos'].append(info)

    def add_finding(self, finding):
        self.host['findings'].append(finding)
    

class Pipeline(object):
    
    def __init__(self):
        self.plugins = []
        self.output = {}

    def register(self, plugin):
        self.plugins.append(plugin)

    def execute(self, host):
        # give the plugin a helper object to work against
        output = PipelineHostOutput()

        for plugin in self.plugins:
            plugin.process(host, output)
        
        # now store the host output against the ip
        self.output[host['ip_str']] = output.host
        return self.output


class AbstractPlugin(object):

    @abstractmethod
    def process(self, host, output):
        raise NotImplementedError()

    @abstractproperty
    def summary(self):
        raise NotImplementedError()

