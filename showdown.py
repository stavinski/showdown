#!/usr/bin/env python3

import sys
from termcolor import cprint, colored
from ipaddress import ip_address, ip_network
from socket import gethostbyname_ex
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter
from getpass import getpass
from download import Downloader
from logger import Log, LogLevel
from shared import Pipeline, Severity
from plugin import PluginRegistry
from shodanapi import ShodanAPI
from formatters import FormattersRegistry


__VERSION__ = '1.0.0'
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


_DEFAULT_PLUGINS = ['info', 'vulns', 'ssl', 'http', 'files', 'eol']

def get_api_key(args):
    if args.key_file:
         with open(args.key_file, 'r') as key_file:
            return key_file.read().rstrip()
    else:
        api_key = None
        while not api_key:  # keep prompting till we get something
            api_key = getpass(colored('[*] API Key: ', 'yellow'))     

        return api_key


def get_file_ips(args):
    ips = set()

    with args.file as hosts_file:
        for line in hosts_file:
            hostname = line.rstrip()
            if hostname:
                try:
                    ip = ip_address(hostname)
                    ips.add(str(ip))
                except ValueError:
                    print(f"[*] Resolving IP(s) for '{hostname}'")
                    _, __, resolved = gethostbyname_ex(hostname)
                    ips.update(resolved)
            
    return ips


def get_net_ips(args):
    ips = set()
    
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
    log = Log(args.verbose)
    formatter_reg = FormattersRegistry(args)
    plugin_reg = PluginRegistry()
    pipeline = Pipeline()
    plugins = plugin_reg.retrieve_plugins(args.plugins)

    if not args.no_banner:
        print(__BANNER__)

    log.write('[*] Starting up')

    api_key = get_api_key(args)
    ips = args.retrieve_ips(args)
    api = ShodanAPI(api_key)
    log.write('[*] Testing shodan', LogLevel.DEBUG)
    success, result = api.test()
    if success:
        log.write(colored("[*] Successful Shodan call.", 'green'), LogLevel.DEBUG)
        log.write(colored(f"[*] {result}", 'blue'), LogLevel.VERBOSE)
    else:
        raise SystemExit(colored(f"[!] Error calling Shodan: '{result}'.", 'red'))

    log.write(f"[+] IPs: {' '.join(ips)}")
    log.write(f"[+] Plugins: {' '.join(args.plugins)}")

    for plugin in plugins:
        pipeline.register(plugin)

    log.write(colored('[+] Details', 'green'), end=' ')
    log.write(colored('[-] No details', 'red'))
    log.write(f"[+] Processing {len(ips)} hosts: ", end='', flush=True)

    downloader = Downloader(api, args.threads, ips)
    hosts = downloader.download(processed_callback=ip_processed)
    print()

    # no details for any of the hosts, nothing more to do!
    if not hosts:
        log.write(colored('[!] No hosts with details', 'red'))
        return

    # process the hosts through the plugins
    for host in hosts:
        output = pipeline.execute(host)

    formatter = formatter_reg.get(args.formatter)
    with formatter:    
        # delegate to the formatter for the output
        for ip, host in output.items():
            formatter.format(ip, host)
            
    log.write(colored('[*] Done.', 'green'))


if __name__ == '__main__':   
    parser = ArgumentParser(prog='showdown.py', formatter_class=RawDescriptionHelpFormatter, description=__BANNER__)
    subparsers = parser.add_subparsers(title='Input mode', help='Either from file or network address(es).')

    # common args
    parser.add_argument('--key-file', '-kf', help='Shodan API key file, if not provided then API key will be prompted for.')
    parser.add_argument('--plugins','-p', help=f"Plugins to run (defaults: {' '.join(_DEFAULT_PLUGINS)}).", metavar='PLUGIN', nargs='+', default=_DEFAULT_PLUGINS, choices=PluginRegistry.available)
    parser.add_argument('--verbose', '-v', action='count', help='Increase the logging verbosity.', default=0)
    parser.add_argument('--version','-V', action='version', version=__VERSION__)
    parser.add_argument('--threads', '-t', help='Number of threads to use for retrieving hosts (default: %(default)s)', default=10, type=int)
    parser.add_argument('--list-plugins', '-lp', help='Lists plugins available.', action='store_true')
    parser.add_argument('--formatter', '-ft', help='Formatter to use for output (default: %(default)s).', default='console', choices=FormattersRegistry.available)
    parser.add_argument('--output', '-o', help='Output file to use (default: stdout).', type=FileType('w'), default='-', metavar='FILE')
    parser.add_argument('--no-color',help='Outputs to console with no color (default: %(default)s).', action='store_true', default=False)
    parser.add_argument('--min-severity', type=Severity.from_name, help='Minimum severity to report on (default: INFO).', metavar='SEVERITY', choices=Severity.all(), default=Severity.INFO)
    parser.add_argument('--no-banner', '-nb', action='store_true', default=False, help='Prevents the banner from being displayed.')

    # input from file
    file_parser = subparsers.add_parser('file')
    file_parser.add_argument('file', help='Hosts file, can be either hostname or IP address each on newline.', type=FileType('r'), metavar='FILE')
    file_parser.set_defaults(retrieve_ips=get_file_ips)

    # input from supplied networks
    net_parser = subparsers.add_parser('net')
    net_parser.add_argument('network', help='Network range to search using CIDR notation (13.77.161.0/22).', metavar='NETWORK', nargs='+')
    net_parser.set_defaults(retrieve_ips=get_net_ips)

    args = parser.parse_args()

    if args.list_plugins:
        print(__BANNER__)
        print('[*] Available plugins:')
        plugin_reg = PluginRegistry()
        for name, summary in plugin_reg.list():
            cprint(f"[{name}]: {summary}", 'blue')
        
        print('[+] Use with --plugins <plugin1> <plugin2> ...')
        sys.exit()

    try:
        # make sure output file is closed
        with args.output:
            main(args)
    except KeyboardInterrupt:
        raise SystemExit(colored('\n[!] CRTL-C pressed, exiting.', 'red'))