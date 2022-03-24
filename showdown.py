#!/usr/bin/env python3

import argparse
import sys
from termcolor import cprint, colored
from ipaddress import ip_address, ip_network
from socket import gethostbyname_ex
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter
from getpass import getpass
from download import Downloader
from shared import Pipeline, Severity
from plugin import PluginRegistry
from shodanapi import ShodanAPI
from formatters import FormattersRegistry


__VERSION__ = '0.1.0'
__AUTHOR__ = 'Mike Cromwell'
__LOGO__ = colored("""       
███████╗██╗  ██╗ ██████╗ ██╗    ██╗██████╗  ██████╗ ██╗    ██╗███╗   ██╗
██╔════╝██║  ██║██╔═══██╗██║    ██║██╔══██╗██╔═══██╗██║    ██║████╗  ██║
███████╗███████║██║   ██║██║ █╗ ██║██║  ██║██║   ██║██║ █╗ ██║██╔██╗ ██║
╚════██║██╔══██║██║   ██║██║███╗██║██║  ██║██║   ██║██║███╗██║██║╚██╗██║
███████║██║  ██║╚██████╔╝╚███╔███╔╝██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝
""", 'red')
__BANNER__ = __LOGO__ + colored(f"""
    {__VERSION__} {__AUTHOR__}
    """, 'yellow')
__BANNER__ += colored("""Pull back juicy info on external targets from shodan!
""", 'green')

def get_api_key(args):
    if args.key_file:
         with open(args.key_file, 'r') as key_file:
            return key_file.read().rstrip()
    else:
        api_key = None
        while not api_key:  # keep prompting till we get something
            api_key = getpass(colored('[*] API Key: ', 'yellow'))     

        return api_key


def retrieve_ips(args):
    ips = set()

    if args.file:
        with open(args.file, 'r') as hosts_file:
            for host in hosts_file:
                hostname = host.rstrip()
                try:
                    ip = ip_address(hostname.rstrip())
                    ips.add(str(ip))
                except ValueError:
                    print(f"[*] Resolving ips for '{hostname}'")
                    _, __, resolved = gethostbyname_ex(hostname)
                    ips.update(resolved)
        
    if args.network:
        for network in args.network:
            net = ip_network(network)
            ips.update(map(str, net.hosts()))
    
    return ips


def ip_processed(has_details):
    if has_details:
        cprint('+', 'green', end='', flush=True)
    else:
        cprint('-', 'red', end='', flush=True)


def main(args):
    formatter_reg = FormattersRegistry(args)
    plugin_reg = PluginRegistry()
    pipeline = Pipeline()
    plugins = plugin_reg.retrieve_plugins(args.plugins)

    print(__BANNER__)
    print('[*] Starting up')
    
    api_key = get_api_key(args)
    ips = retrieve_ips(args)
    api = ShodanAPI(api_key)
    print('[*] Testing shodan')
    success, result = api.test()
    if success:
        cprint("[*] Successful Shodan call.", 'green')
        cprint(f"[*] {result}", 'blue')
    else:
        raise SystemExit(colored(f"[!] Error calling Shodan: '{result}'.", 'red'))

    print(f"[+] IPs: {','.join(ips)}")
    print(f"[+] Plugins: {' '.join(args.plugins)}")

    for plugin in plugins:
        pipeline.register(plugin)

    cprint('[+] Details', 'green', end=' ')
    cprint('[-] No details', 'red')
    print(f"[+] Processing {len(ips)} hosts: ", end='', flush=True)

    downloader = Downloader(api, args.threads, ips)
    hosts = downloader.download(processed_callback=ip_processed)
    print()

    # no details for any of the hosts, nothing more to do!
    if not hosts:
        cprint('[!] No hosts with details', 'red')
        return

    # process the hosts through the plugins
    for host in hosts:
        output = pipeline.execute(host)

    formatter = formatter_reg.get(args.formatter)
    with formatter:    
        # delegate to the formatter for the output
        for ip, host in output.items():
            formatter.format(ip, host)
            
    cprint('[*] Done.', 'green')
    args.output.close()


if __name__ == '__main__':   
    parser = ArgumentParser(prog='showdown.py', formatter_class=RawDescriptionHelpFormatter, description=__BANNER__)
    parser.add_argument('--file', '-f', help='Hosts file, can be either hostname or IP address.')
    parser.add_argument('--network', '--n', help='Network range to search using CIDR notation (13.77.161.0/22); supports multiple.', action='append')
    parser.add_argument('--key-file', '-kf', help='Shodan API key file, if not provided then API key will be prompted for.')
    parser.add_argument('--plugins','-p', help='Plugins to run, defaults to info vulns.', nargs='+', default=['info', 'vulns'], choices=PluginRegistry.available)
    parser.add_argument('--verbose', '-v', action='count', help='Increase the logging verbosity.', default=0)
    parser.add_argument('--version','-V', action='version', version=__VERSION__)
    parser.add_argument('--threads', '-t', help='Number of threads to use for retrieving hosts. Defaults to 10', default=10, type=int)
    parser.add_argument('--list-plugins', '-lp', help='Lists plugins available.', action='store_true')
    parser.add_argument('--formatter', '-ft', help='Formatter to use for output, default is console.', default='console', choices=FormattersRegistry.available)
    parser.add_argument('--output', '-o', help='Output file to use, default is stdout.', type=FileType('w'), default='-', metavar='FILE')
    parser.add_argument('--no-color',help='Outputs to console with no color. Default is False.', action='store_true', default=False)
    parser.add_argument('--min-severity', type=Severity.from_name, help='Minimum severity to report on. Default is INFO.', choices=Severity.all(), default=Severity.INFO)

    args = parser.parse_args()

    if args.list_plugins:
        print(__BANNER__)
        print('[*] Available plugins:')
        plugin_reg = PluginRegistry()
        for name, summary in plugin_reg.list():
            cprint(f"[{name}]: {summary}", 'blue')
        
        print('[+] Use with --plugins <plugin1> <plugin2> ...')
        sys.exit()

    if not args.file and not args.network:
        raise SystemExit(colored('[!] Must provide either a file or network to search against, see usage with -h.', 'red'))

    try:
        main(args)
    except KeyboardInterrupt:
        raise SystemExit(colored('\n[!] CRTL-C pressed, exiting.', 'red'))