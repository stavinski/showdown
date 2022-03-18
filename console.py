
from gettext import find
from termcolor import cprint
from shared import Severity


class Console(object):

    COLORS = {
        Severity.CRITICAL: ('white', 'on_red'),
        Severity.HIGH: ('red', None),
        Severity.MEDIUM: ('yellow', None),
        Severity.LOW: ('green', None),
        Severity.INFO: ('cyan', None),
    }

    def echo(self, severity, val):
        fg, bg = Console.COLORS[severity]
        if bg:
            cprint(val, fg, bg)
        else:
            cprint(val, fg)

    def print_info(self, info):
        cprint(f"[INFO] {info['description']}", 'blue')

    def print_finding(self, finding):
        
        severity = finding['severity']
        if 'port' in finding and 'protocol' in finding:
            self.echo(severity, f"[{finding['port']}/{finding['protocol']}] => {finding['summary']}")
        else:
            self.echo(severity, f"[+] {finding['summary']}")

        if 'items' in finding:
            for item in finding['items']:
                cprint(f"\t[+] {item['summary']}", 'cyan')
        
        if 'references' in finding:
            for reference in finding['references']:
                cprint(f"\t[+] {reference}", 'blue')