
from shared import AbstractPlugin, Finding, Severity


class Plugin(AbstractPlugin):
    
    def process(self, host, output):
        for data in host['data']:
            if 'smb' in data:
                self.check_smb(data, output)

    
    def check_smb(self, data, output):
        smb = data['smb']
        shares = smb.get('shares', None)
        
        if smb['anonymous']:
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


    @property
    def summary(self):
        return 'Details of any files found, such as FTP or SMB.'