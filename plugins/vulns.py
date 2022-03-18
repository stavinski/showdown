from shared import AbstractPlugin, Severity


class Plugin(AbstractPlugin):

    def process(self, host, output):
        if not 'vulns' in host or not host['vulns']:
            return  # no vulns exit early

        total = 0
        highest_severity = Severity.INFO
        for data in host['data']:
            if 'vulns' not in data:
                continue
                    
            for key, vuln in data['vulns'].items():
                total += 1
                cvss = float(vuln['cvss'])
                severity = self.map_severity(cvss)
                if severity.value > highest_severity.value:
                    highest_severity = severity
        
        output.add_finding({
            'id': 'vulns_count',
            'summary': f"Found {total} vulnerabilities",
            'severity': highest_severity
        })

        for data in host['data']:
            if 'vulns' not in data:
                continue

            for key, vuln in data['vulns'].items():
                cvss = float(vuln['cvss'])
                severity = self.map_severity(cvss)
                output.increase_score(cvss * 100)
                output.add_finding({
                    'id': 'vuln_' + key.replace('-', '_'),
                    'severity': severity,
                    'port': data['port'],
                    'protocol': data['transport'],
                    'summary': vuln['summary'],
                    'references': vuln['references'],
                    'items': [{
                        'summary': f"Verified: {vuln['verified']}"
                    }]
                })


    @property
    def summary(self):
        return 'Provides details for any vulnerabilities discovered'

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
