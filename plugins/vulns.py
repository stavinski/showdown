from shared import AbstractPlugin, Severity


class Plugin(AbstractPlugin):

    @property
    def summary(self):
        return 'Details of any vulnerabilities for the host'

    def process(self, host, state):
        if 'vulns' in host and host['vulns']:
            total = len(host['vulns'])
            state.add_issue(host, Severity.HIGH, f"Found {total} vulnerabilities")
            state.increase_score(host, 500)
        else:
            return

        for data in host['data']:
            if 'vulns' not in data:
                continue

            for key, vuln in data['vulns'].items():
                cvss = float(vuln['cvss'])
                severity = self.map_severity(cvss)
                state.increase_score(host, cvss * 100)
                additional = { 'verified': vuln['verified'], 'references': vuln['references'] }
                state.add_issue(host, severity, f"[{severity.name}] {data['port']}/{data['transport']} {key} - {vuln['summary']}", additional=additional)


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
