from shared import AbstractFormatter
from csv import writer as Writer

class CSVFormatter(AbstractFormatter):
    
    def __init__(self, args):
        super().__init__()
        self.args = args            
        self.writer = Writer(self.args.output)
    
    def begin(self):
        self.writer.writerow(['ip', 'score', 'port', 'protocol', 'id', 'value', 'summary', 'severity', 'references', 'items'])

    def format(self, ip, host):
        self.host(ip, host)
        self.findings(host.findings)

    def host(self, ip, host):
        self.ip = ip
        self.score = host.score

    def findings(self, findings):
        for finding in findings:
            self.writer.writerow([self.ip, 
                self.score, 
                finding.id, 
                finding.port, 
                finding.protocol, 
                finding.value, 
                finding.summary, 
                finding.severity.name, 
                ';'.join(finding.references), 
                ';'.join(finding.items)]
            )
