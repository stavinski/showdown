#!/usr/bin/env python3


import pathlib
import pkgutil
from termcolor import cprint, colored
from ipaddress import ip_address
from socket import gethostbyname_ex
from shodan import Shodan, Shodan
from shodan.exception import APIError
from argparse import ArgumentParser, RawDescriptionHelpFormatter, RawTextHelpFormatter
from getpass import getpass

from shared import Pipeline
from console import Console

import importlib
import plugins



__VERSION__ = '0.1.0'
__AUTHOR__ = 'Mike Cromwell'


# find plugins that are available
AVAILABLE_PLUGINS = [name for finder, name, ispkg in pkgutil.iter_modules(plugins.__path__)]
LOADED_PLUGINS = { plugin: importlib.import_module(f"plugins.{plugin}",'plugins').Plugin() for plugin in AVAILABLE_PLUGINS}

def build_plugins(plugins):
    for plugin in plugin:
        yield LOADED_PLUGINS[plugin]

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

    host = api.host('81.27.104.119')

    pipeline = Pipeline()
    console = Console()
    plugins = build_plugins(args.plugins)

    print(f"[*] Using plugins: {','.join(args.plugins)}")

    for plugin in plugins:
        pipeline.add_plugin(plugin)
    
    state = pipeline.execute(host)
    cprint("="* 100, 'magenta')
    cprint(f"Results for: {host['ip_str']}", 'magenta')
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
    parser.add_argument('-f', '--file', help='Hosts file, can be either hostname or IP address.')
    parser.add_argument('-n', '--network', help='Network range to search using CIDR notation (13.77.161.0/22).')
    parser.add_argument('-kf', '--key-file', help='Shodan API key file, if not provided then API key will be prompted for.')
    parser.add_argument('-p', '--plugins', help='Plugins to run as comma separated list, defaults to info,vulns.', type=list, default=['info', 'vulns'], choices=AVAILABLE_PLUGINS)
    parser.add_argument('-v', '--verbose', action='count', help='Increase the logging verbosity.', default=0)
    parser.add_argument('-V', '--version', action='version', version=__VERSION__)

    args = parser.parse_args()

    if not args.file and not args.network:
        raise SystemExit(colored('[!] Must provide either a file or network to search against, see usage with -h.', 'red'))

    if len(args.plugins) <= 0:
        raise SystemExit(colored('[!] No plugins provided.'))

    try:
        main(args)
    except KeyboardInterrupt:
        raise SystemExit(colored('\n[!] CRTL-C pressed, exiting.', 'red'))