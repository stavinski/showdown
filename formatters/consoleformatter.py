from termcolor import cprint
from shared import Severity, AbstractFormatter

class ConsoleFormatter(AbstractFormatter):

    COLORS = {
        Severity.CRITICAL: ('white', 'on_red'),
        Severity.HIGH: ('red', None),
        Severity.MEDIUM: ('yellow', None),
        Severity.LOW: ('green', None),
        Severity.INFO: ('cyan', None),
    }

    def __init__(self,args):
        super().__init__()
        self.args = args

    def print(self, val, fore_color, bg_color=None):
        if self.args.no_color:
            print(val, file=self.args.output)
        else:
            cprint(val, fore_color, bg_color, file=self.args.output)

    def echo(self, severity, val):
        fg, bg = ConsoleFormatter.COLORS[severity]
        self.print(val, fg, bg)
        
    def host(self, ip, host):
        self.print("="* 100, 'magenta')
        self.print(f"Host: {ip} Score: {int(host['score'])} - https://www.shodan.io/host/{ip}", 'magenta')
        self.print("="* 100, 'magenta')

    def infos(self, infos):
        for info in infos:
            self.print_info(info)

    def print_info(self, info):
        self.print(f"[INFO] {info['summary']}", 'blue')

    def findings(self, findings):
        for finding in findings:
            self.print_finding(finding)

    def print_finding(self, finding):
        
        severity = finding['severity']
        if 'port' in finding and 'protocol' in finding:
            self.echo(severity, f"[{finding['port']}/{finding['protocol']}] => {finding['summary']}")
        else:
            self.echo(severity, f"[+] {finding['summary']}")

        if 'items' in finding:
            for item in finding['items']:
                self.print(f"\t[+] {item}", 'cyan')
        
        if 'references' in finding:
            for reference in finding['references']:
                self.print(f"\t[+] {reference}", 'blue')
