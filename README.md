# SHOWDOWN

## Summary

Showdown is a tool that utilises shodan in order to find targets of interest, it should be used at the start of an external test whilst other scans and enumeration are being performed, and allows for an efficient way of knowing which targets should be focused on initially.

It uses a plugin model and comes with built-in plugins to that should give good coverage on items such as vulnerabilities, SSL/TLS however if there are certain items not covered that you need then it's simple to write your own to cover these and better still send a PR to get it introduced to the built-in library!

## Install

I would ussually recommend setting up a venv environment to not clobber other libraries, this can be done by installing venv using your package manager (i.e. `sudo apt install python3-venv`).

Once this is done you can then clone the repo, setup venv and install the libraries from pip:

~~~
git@github.com:stavinski/showdown.git
cd showdown
python3 -m venv .venv  # setup a venv environment in .venv dir
source .venv/bin/activate  # activate the venv, use deactivate to revert back
pip install -r requirements.txt
~~~

This should allow you to now use the application, of course you could forgo using venv and just install the requirements globally.

## Screencast

[![Showdown in use](https://asciinema.org/a/482371.svg)](https://asciinema.org/a/482371)

## Usage


```
usage: showdown.py [-h] [--key-file KEY_FILE] [--plugins PLUGIN [PLUGIN ...]] [--verbose] [--version] [--threads THREADS] [--list-plugins] [--formatter {console,csv}] [--output FILE]
                   [--no-color] [--min-severity SEVERITY]
                   {file,net} ...

       
███████╗██╗  ██╗ ██████╗ ██╗    ██╗██████╗  ██████╗ ██╗    ██╗███╗   ██╗
██╔════╝██║  ██║██╔═══██╗██║    ██║██╔══██╗██╔═══██╗██║    ██║████╗  ██║
███████╗███████║██║   ██║██║ █╗ ██║██║  ██║██║   ██║██║ █╗ ██║██╔██╗ ██║
╚════██║██╔══██║██║   ██║██║███╗██║██║  ██║██║   ██║██║███╗██║██║╚██╗██║
███████║██║  ██║╚██████╔╝╚███╔███╔╝██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝

    1.0.0 Mike Cromwell
    Pull back juicy info on external targets from shodan!


optional arguments:
  -h, --help            show this help message and exit
  --key-file KEY_FILE, -kf KEY_FILE
                        Shodan API key file, if not provided then API key will be prompted for.
  --plugins PLUGIN [PLUGIN ...], -p PLUGIN [PLUGIN ...]
                        Plugins to run (defaults: info vulns ssl http shares).
  --verbose, -v         Increase the logging verbosity.
  --version, -V         show program's version number and exit
  --threads THREADS, -t THREADS
                        Number of threads to use for retrieving hosts (default: 10)
  --list-plugins, -lp   Lists plugins available.
  --formatter {console,csv}, -ft {console,csv}
                        Formatter to use for output (default: console).
  --output FILE, -o FILE
                        Output file to use (default: stdout).
  --no-color            Outputs to console with no color (default: False).
  --min-severity SEVERITY
                        Minimum severity to report on (default: INFO).

Input mode:
  {file,net}            Either from file or network address(es).
```

Find findings rated medium or above from hosts in file `hosts.txt`, use shodan key file `shodan.key`:

~~~ sh
python3 showdown.py --min-severity MEDIUM --key-file shodan.key file hosts.txt
~~~

Find SSL/TLS findings in network `103.71.205.0/24` and prompt for API key:

~~~ sh
python3 showdown.py --plugins ssl net 103.71.205.0/24
~~~

## Plugins

To create a new plugin:

1. Create a new python file inside of the `plugins` directory (no spaces) this will act as the name so suggest a short name to convey what will be parsed such as `cloud.py`.
2. Implement the required class structure, for example:

```python
from shared import AbstractPlugin, Severity, Finding

class Plugin(AbstractPlugin):

    def process(self, host, output):
        # populate using the output helper object, for example:
        output.add_finding(Finding(
                        'finding_key',
                        val,
                        'Summary',
                        port,
                        Severity.MEDIUM,
                        proto
                    ))
        output.increase_score(50)

    @property
    def summary(self):
        return 'Cloud details about the host'
```
3. That is all that is needed for the plugin to be registered with showdown.py. When you run the `--list-plugins` you should see the plugin has been added to the list.
4. To use the plugin simply add it into the list of plugins, `python3 showdown.py --key-file shodan.key --plugins vulns cloud ...`

## FAQs

**Q. Why does it take a while to return results?**

**A.** Shodan is rate limited to 1 request per second. Showdown does try to be as efficient as it can by utilising separate threads to make the request so that if a request is taking a while to respond it is not penalised by this delay. That being said it is still restricted to making calls once per second. Another option is batching IPs however this is only permitted on the Enterprise plan which I do not have so I cannot test against this approach.

**Q. Can I run against a single host?**

**A.** I mean you can using the `--network` argument and simply using a CIDR length of `/32` for example `--network 8.8.8.8/32` however this isn't really the intended purpose of the tool which was to cover a broad number of targets and help identify hosts to check first whilst waiting for other scans etc...


## TODO

- [X] List plugins
- [X] Tidy up queueing and threading
- [X] Add CSV output
- [X] Common Data Structure for results
- [X] Sorting hosts based off score
- [X] Plugin: Cloud
- [X] Plugin: SSL
- [X] Minium severity argument
- [X] Plugin: HTTP
- [X] Wire up verbosity
- [ ] Plugin: Shares
- [ ] Plugin: Interesting Ports
