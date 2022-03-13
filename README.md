# Showdown.py

## Summary

Tool that can allows (tailored) juicy information to be retrieved from shodan for external targets. This is possible as it uses a plugin model to allow use of built-in plugins or custom created ones when deciding what information to be returned.

## Usage

```
usage: showdown.py [-h] [-f FILE] [-n NETWORK] [-kf KEY_FILE] [-p {info,vulns} [{info,vulns} ...]] [-v] [-V] [-t THREADS]

       
███████╗██╗  ██╗ ██████╗ ██╗    ██╗██████╗  ██████╗ ██╗    ██╗███╗   ██╗
██╔════╝██║  ██║██╔═══██╗██║    ██║██╔══██╗██╔═══██╗██║    ██║████╗  ██║
███████╗███████║██║   ██║██║ █╗ ██║██║  ██║██║   ██║██║ █╗ ██║██╔██╗ ██║
╚════██║██╔══██║██║   ██║██║███╗██║██║  ██║██║   ██║██║███╗██║██║╚██╗██║
███████║██║  ██║╚██████╔╝╚███╔███╔╝██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝

    0.1.0 Mike Cromwell
    Pull back juicy info on external targets from shodan!


optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Hosts file, can be either hostname or IP address.
  -n NETWORK, --network NETWORK
                        Network range to search using CIDR notation (13.77.161.0/22); supports multiple.
  -kf KEY_FILE, --key-file KEY_FILE
                        Shodan API key file, if not provided then API key will be prompted for.
  -p {info,vulns} [{info,vulns} ...], --plugins {info,vulns} [{info,vulns} ...]
                        Plugins to run, defaults to info vulns.
  -v, --verbose         Increase the logging verbosity.
  -V, --version         show program's version number and exit
  -t THREADS, --threads THREADS
                        Number of threads to use for retrieving hosts. Defaults to 10
```

## Plugins

To create a new plugin:

1. Create a new python file inside of the `plugins` directory (no spaces) this will act as the name so suggest a short name to convey what will be parsed such as `cloud.py`.
2. Implement the required class structure, for example:

```python
from shared import AbstractPlugin, Severity

class Plugin(AbstractPlugin):

    def process(self, host, state):
        # do stuff here...
        # retrieve cloud details

    @property
    def summary(self):
        return 'Cloud details about the host'
```
3. That is all that is needed for the plugin to be registered with showdown.py. When you run the `--help` you should see the plugin has been added to the `--plugins` argument.
4. To use the plugin simply add it into the list of plugins, `python3 showdown.py --key-file shodan.key --plugins vulns cloud ...`
