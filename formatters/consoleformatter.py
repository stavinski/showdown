from termcolor import cprint
from shared import Severity


class ConsoleFormatter(object):

    COLORS = {
        Severity.CRITICAL: ('white', 'on_red'),
        Severity.HIGH: ('red', None),
        Severity.MEDIUM: ('yellow', None),
        Severity.LOW: ('green', None),
        Severity.INFO: ('cyan', None),
    }

    def echo(self, severity, val):
        fg, bg = ConsoleFormatter.COLORS[severity]
        if bg:
            cprint(val, fg, bg)
        else:
            cprint(val, fg)

    def print_host(self, ip, host):
        cprint("="* 100, 'magenta')
        cprint(f"Host: {ip} Score: {int(host['score'])} - https://www.shodan.io/host/{ip}", 'magenta')
        cprint("="* 100, 'magenta')

    def print_infos(self, infos):
        for info in infos:
            self.print_info(info)

    def print_info(self, info):
        cprint(f"[INFO] {info['description']}", 'blue')

    def print_findings(self, findings):
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
                cprint(f"\t[+] {item['summary']}", 'cyan')
        
        if 'references' in finding:
            for reference in finding['references']:
                cprint(f"\t[+] {reference}", 'blue')