from shared import AbstractFormatter
from csv import writer as Writer

class CSVFormatter(AbstractFormatter):
    
    def __init__(self, args):
        super().__init__()
        self.args = args            
        self.writer = Writer(self.args.output)
    
    def begin(self):
        self.writer.writerow(['ip', 'score', 'port', 'protocol', 'id', 'value', 'summary', 'severity', 'references', 'items'])

    def host(self, ip, host):
        self.ip = ip
        self.score = int(host['score'])

    def infos(self, infos):
        for info in infos:
            self.writer.writerow([self.ip, self.score, info['id'], '', '', info['value'], info['summary']])

    def findings(self, findings):
        for finding in findings:
            references = finding.get('references', [])
            items = finding.get('items', [])
            port = finding.get('port', '')
            protocol = finding.get('protocol', '')
            self.writer.writerow([self.ip, self.score, finding['id'], port, protocol, finding['value'], finding['summary'], finding['severity'].name, ';'.join(references), ';'.join(items)])
