from click import echo
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

    def newline(self):
        print(file=self.args.output)

    def print(self, val, fore_color=None, bg_color=None, end=None):
        if self.args.no_color:
            print(val, file=self.args.output, end=end)
        else:
            cprint(val, fore_color, bg_color, file=self.args.output, end=end)

    def begin(self):
        if not self.args.no_color:
            self._print_key()

    def echo(self, severity, val, end=None):
        fg, bg = ConsoleFormatter.COLORS[severity]
        self.print(val, fg, bg, end=end)

    def format(self, ip,  host):
        self.host(ip, host)
        self.findings(host.findings)

    def host(self, ip, host):
        self.print("="* 100, 'magenta')
        self.print(f"Host: {ip} Score: {host.score} - https://www.shodan.io/host/{ip}", 'magenta')
        self.print("="* 100, 'magenta')

    def findings(self, findings):
        for finding in findings:
            self.print_finding(finding)

    def print_finding(self, finding):
        severity = finding.severity
        if finding.has_port:
            self.echo(severity, f"[{finding.port}/{finding.protocol}] => {finding.summary}")
        else:
            self.echo(severity, f"[+] {finding.summary}")

        for item in finding.items:
            self.print(f"\t[+] {item}", 'cyan')
    
        for reference in finding.references:
            self.print(f"\t[+] {reference}", 'blue')

    def _print_key(self):
        self.print('[+] Key: ', end='')
        for severity in Severity.all():
            self.echo(severity, severity.name, end=' ')
        self.newline()