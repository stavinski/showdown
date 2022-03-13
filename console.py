
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
