#!/usr/bin/env python3

from queue import Queue
from re import T
import sys
import threading
from time import sleep
from termcolor import cprint, colored
from ipaddress import ip_address, ip_network
from socket import gethostbyname_ex
from argparse import ArgumentParser, RawDescriptionHelpFormatter, RawTextHelpFormatter
from getpass import getpass
from shared import Pipeline, Severity
from plugin import PluginRegistry
from console import Console
from shodanapi import ShodanAPI


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


def download_host(api, queue, results):
    while True:
        ip = queue.get()
        try:
            success, ip, result = api.host(ip)
            if success:
                results.append(result)
                print(colored('+', 'green'), end='', flush=True)
            else:
                print(colored('-', 'red'), end='', flush=True)
        finally:
            queue.task_done()


def main(args):
    console = Console()
    plugin_reg = PluginRegistry()
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
    
    pipeline = Pipeline()
    plugins = plugin_reg.retrieve_plugins(args.plugins)

    print(f"[*] Using plugins: {' '.join(args.plugins)}")

    for plugin in plugins:
        pipeline.add_plugin(plugin)

    num_hosts = len(ips)
    work_queue = Queue(num_hosts)
    hosts = []
    for count in range(0, args.threads):
        t = threading.Thread(target=download_host, name=f'downloader-{count}', args=(api, work_queue, hosts))
        t.setDaemon(True)
        t.start()
    
    cprint('[+] Details', 'green')
    cprint('[-] No details', 'red')
    
    print(f"[+] Processing {num_hosts} hosts: ", end='', flush=True)
    for ip in ips:
        work_queue.put(ip)
        sleep(1)  # shodan API is rate limited to 1req/sec so leave a 1 sec gap between pushing the work onto the queue

    work_queue.join()
    print()

    # no details for any of the hosts, nothing more to do!
    if not hosts:
        cprint('[!] No hosts with details', 'red')
        return

    # process the hosts through the plugins
    for host in hosts:
        ip = host['ip_str']
        state = pipeline.execute(host)


    for ip, host in state.hosts.items():
        cprint("="* 100, 'magenta')
        cprint(f"Host: {ip} - https://www.shodan.io/host/{ip}", 'magenta')
        cprint("="* 100, 'magenta')
        for issue in host.issues:
            console.echo(issue.severity, '\t' + issue.desc)



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