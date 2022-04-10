
from shared import AbstractPlugin, Finding, Severity


class Plugin(AbstractPlugin):
    
    def process(self, host, output):
        for data in host['data']:
            if 'smb' in data:
                self.check_smb(data, output)

            if 'ftp' in data:
                self.check_ftp(data, output)

            if 'afp' in data:
                self.check_afp(data, output)

    def check_smb(self, data, output):
        smb = data['smb']
        shares = smb.get('shares', None)
        
        if smb.get('anonymous', None):
            output.add_finding(Finding(
                    f"smb_anon",
                    True,
                    'Anonymous SMB access.',
                    data['port'],
                    Severity.HIGH,
                    data['transport']
                ))
            output.increase_score(200)

        if shares:
            items = [f"{share['name']} {share['comments']}" for share in shares]

            output.add_finding(Finding(
                    f"smb_shares",
                    True,
                    'Discovered SMB shares',
                    data['port'],
                    Severity.HIGH,
                    data['transport'],
                    items=items
                ))
            output.increase_score(100)

    def check_ftp(self, data, output):
        ftp = data['ftp']
        if ftp.get('anonymous', None):
            output.add_finding(Finding(
                    f"ftp_anon",
                    True,
                    'Anonymous FTP access.',
                    data['port'],
                    Severity.HIGH,
                    data['transport']
                ))
            output.increase_score(200)

    def check_afp(self, data, output):
        afp = data['afp']
        output.add_finding(Finding(
                f"afp_exposed",
                f"{afp['utf8_server_name']} ({afp['machine_type']})",
                f"AFP exposed: {afp['utf8_server_name']} ({afp['machine_type']})",
                data['port'],
                Severity.INFO,
                data['transport']
            ))

        uams = afp.get('uams', [])
        for uam in uams:
            if uam == 'No User Authent':
                output.add_finding(Finding(
                f"afp_no_auth",
                True,
                'AFP No Auth enabled.',
                data['port'],
                Severity.HIGH,
                data['transport']
            ))
            output.increase_score(200)

            if uam == 'Cleartxt Passwrd':
                output.add_finding(Finding(
                f"afp_clear_text",
                True,
                'AFP Clear text password enabled.',
                data['port'],
                Severity.HIGH,
                data['transport']
            ))
            output.increase_score(100)

            if uam == 'Randnum exchange':
                output.add_finding(Finding(
                f"afp_randnum_pwd",
                True,
                'AFP Randnum password enabled.',
                data['port'],
                Severity.MEDIUM,
                data['transport']
            ))
            output.increase_score(50)


    @property
    def summary(self):
        return 'Details of any files found, such as FTP or SMB.'