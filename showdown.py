#!/usr/bin/env python3

from termcolor import cprint, colored
from ipaddress import ip_address, ip_network
from socket import gethostbyname_ex
from shodan import Shodan, Shodan
from shodan.exception import APIError
from argparse import ArgumentParser, RawDescriptionHelpFormatter, RawTextHelpFormatter
from getpass import getpass
from shared import Pipeline, Severity
from console import Console

import importlib
import pkgutil
import plugins


__VERSION__ = '0.1.0'
__AUTHOR__ = 'Mike Cromwell'


# find plugins that are available
AVAILABLE_PLUGINS = [name for finder, name, ispkg in pkgutil.iter_modules(plugins.__path__)]
LOADED_PLUGINS = { plugin: importlib.import_module(f"plugins.{plugin}",'plugins').Plugin() for plugin in AVAILABLE_PLUGINS}

def build_plugins(plugins):
    for plugin in plugins:
        yield LOADED_PLUGINS[plugin]

def test_shodan(api):
    try:
        info = api.info()
        cprint("[*] Successful Shodan call.", 'green')
        cprint(f"[*] {info}", 'blue')
    except APIError as e:
        raise SystemExit(colored(f"[!] Error calling Shodan: '{e}'.", 'red'))


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


def main(args):
    console = Console()
    api_key = get_api_key(args)
    ips = retrieve_ips(args)
    api = Shodan(api_key)
    test_shodan(api)

    print(f"[+] Resolved ips: {','.join(ips)}")

    host = api.host('81.27.104.119')

    print('[*] Issue Key:')
    for severity in Severity.all():
        console.echo(severity, severity.name)

    pipeline = Pipeline()
    plugins = build_plugins(args.plugins)

    print(f"[*] Using plugins: {' '.join(args.plugins)}")

    for plugin in plugins:
        pipeline.add_plugin(plugin)
    
    state = pipeline.execute(host)
    cprint("="* 100, 'magenta')
    cprint(f"Host: {host['ip_str']}", 'magenta')
    cprint("="* 100, 'magenta')
    for issue in state.issues:
        console.echo(issue.severity, '\t' + issue.desc)


if __name__ == '__main__':
    logo = colored("""       
███████╗██╗  ██╗ ██████╗ ██╗    ██╗██████╗  ██████╗ ██╗    ██╗███╗   ██╗
██╔════╝██║  ██║██╔═══██╗██║    ██║██╔══██╗██╔═══██╗██║    ██║████╗  ██║
███████╗███████║██║   ██║██║ █╗ ██║██║  ██║██║   ██║██║ █╗ ██║██╔██╗ ██║
╚════██║██╔══██║██║   ██║██║███╗██║██║  ██║██║   ██║██║███╗██║██║╚██╗██║
███████║██║  ██║╚██████╔╝╚███╔███╔╝██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝
""", 'red')

    desc = logo + colored(f"""
    {__VERSION__} {__AUTHOR__}
    """, 'yellow')

    desc += colored("""Pull back juicy info on external targets from shodan!
""", 'green')
    
    parser = ArgumentParser(
            prog='showdown.py',
            formatter_class=RawDescriptionHelpFormatter,
            description=desc)
    parser.add_argument('--file', '-f', help='Hosts file, can be either hostname or IP address.')
    parser.add_argument('--network', '--n', help='Network range to search using CIDR notation (13.77.161.0/22); supports multiple.', action='append')
    parser.add_argument('--key-file', '-kf', help='Shodan API key file, if not provided then API key will be prompted for.')
    parser.add_argument('--plugins','-p', help='Plugins to run, defaults to info vulns.', nargs='+', default=['info', 'vulns'], choices=AVAILABLE_PLUGINS)
    parser.add_argument('--verbose', '-v', action='count', help='Increase the logging verbosity.', default=0)
    parser.add_argument('--version','-V', action='version', version=__VERSION__)
    parser.add_argument('--threads', '-t', help='Number of threads to use for retrieving hosts. Defaults to 10', default=10, type=int)

    args = parser.parse_args()

    if not args.file and not args.network:
        raise SystemExit(colored('[!] Must provide either a file or network to search against, see usage with -h.', 'red'))

    try:
        main(args)
    except KeyboardInterrupt:
        raise SystemExit(colored('\n[!] CRTL-C pressed, exiting.', 'red'))