#!/usr/bin/env python3

from os import stat
from termcolor import cprint, colored
from ipaddress import ip_address
from socket import gethostbyname_ex
from shodan import Shodan, Shodan
from shodan.exception import APIError
from argparse import ArgumentParser
from getpass import getpass

from shared import Severity, Filter, Pipeline
from console import Console

import json

class InfoFilter(Filter):

    def process(self, host, state):
        if host['os']:
            state.add_issue(Severity.INFO, f"OS: {host['os']}")

        state.add_issue(Severity.INFO, f"Last Updated: {host['last_update']}")


class VulnsFilter(Filter):

    def process(self, host, state):
        if host['vulns']:
            total = len(host['vulns'])
            state.add_issue(Severity.HIGH, f"Found {total} vulnerabilities")
            state.increase_score(500)

        for data in host['data']:
            if 'vulns' not in data:
                continue

            for key, vuln in data['vulns'].items():
                cvss = float(vuln['cvss'])
                severity = self.map_severity(cvss)
                state.increase_score(severity.value * 100)
                additional = { 'verified': vuln['verified'], 'references': vuln['references'] }
                state.add_issue(severity, f"[{severity.name}] {data['port']}/{data['transport']} {key} - {vuln['summary']}", additional=additional)

    def map_severity(self, cvss):
        mappings = [
            (0.0, 0.0, Severity.INFO),
            (1.0, 3.9, Severity.LOW),
            (4.0, 6.9, Severity.MEDIUM),
            (7.0, 9.9, Severity.HIGH),
            (10.0, 10.0, Severity.CRITICAL)
        ]

        if cvss < 0 or cvss > 10:
            raise ValueError(f"CVSS score {cvss} was invalid, value needs to be between 0 and 10.")

        for lower, upper, severity in mappings:
            if cvss >= lower and cvss <= upper:
                return severity


def main(args):
    api_key = None
    ips = set()

    if args.key_file:
         with open(args.key_file, 'r') as key_file:
            api_key = key_file.read().rstrip()
    else:
        while not api_key:  # keep prompting till we get something
            api_key = getpass(colored('[*] API Key: ', 'yellow'))     
    
    api = Shodan(api_key)
    try:
        info = api.info()
        cprint("[*] Successful Shodan call.", 'green')
        print(f"[*] Plan: {info['plan']}")
    except APIError as e:
        raise SystemExit(colored(f"[!] Error calling Shodan: '{e}'.", 'red'))

    with open(args.file, 'r') as hosts_file:
        for host in hosts_file:
            hostname = host.rstrip()
            try:
                ip = ip_address(hostname.rstrip())
            except ValueError:
                print(f"[*] Resolving ips for '{hostname}'")
                _, __, resolved = gethostbyname_ex(hostname)
                ips.update(resolved)
        
    print(f"[+] Resolved ips: {','.join(ips)}")

    host = api.host('x.x.x.x')

    pipeline = Pipeline()
    filters = [InfoFilter(), VulnsFilter()]
    console = Console()

    for filter in filters:
        pipeline.add_filter(filter)
    
    state = pipeline.execute(host)
    for issue in state.issues:
        console.echo(issue.severity, '\t' + issue.desc)


if __name__ == '__main__':
    parser = ArgumentParser('Showdown - Performs shodan query on hosts to point out potential findings and focus on places to look, handy to get a head start for external assessments!')
    parser.add_argument('-f', '--file', help='Hosts file, can be either hostname or IP address.')
    parser.add_argument('-n', '--network', help='Network range to search using CIDR notation (13.77.161.0/22).')
    parser.add_argument('-kf', '--key-file', help='Shodan API key file, if not provided then API key will be prompted for.')

    args = parser.parse_args()

    if not args.file and not args.network:
        raise SystemExit(colored('[!] Must provide either a file or network to search against, see usage with -h.', 'red'))

    try:
        main(args)
    except KeyboardInterrupt:
        raise SystemExit(colored('\n[!] CRTL-C pressed, exiting.', 'red'))