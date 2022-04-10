
from shared import AbstractPlugin, Finding, Severity


class Plugin(AbstractPlugin):

    WEAK_KEX_ALGOS = [
        'diffie-hellman-group-exchange-sha1',
        'diffie-hellman-group1-sha1',
        'gss-gex-sha1-',
        'gss-group1-sha1-',
        'gss-group14-sha1-',
        'rsa1024-sha1'
    ]

    WEAK_ENC_ALGOS = [
        '3des-',
        'arcfour-'
        'blowfish-',
        'cast128-',
        'rijndael-'
    ]

    WEAK_MAC_ALGOS = [
        'md5',
        'sha1',
        'umac-64'
    ]

    def process(self, host, output):
        for data in host['data']:
            if 'ssh' in data: 
                ssh = data['ssh']
                version = data['version']

                if version == '1.0':
                    output.add_finding(Finding(
                        f"ssh_version_1_0",
                        version,
                        f"SSH version: {version}",
                        data['port'],
                        Severity.LOW,
                        data['transport']
                    ))
                    output.increase_score(20)


                if 'kex' in data['ssh']:
                    kex = ssh['kex']
                    
                    for algo in kex.get('kex_algorithms', []):
                        for check in Plugin.WEAK_KEX_ALGOS:
                            if check in algo:
                                output.add_finding(Finding(
                                    f"ssh_weak_kex",
                                    algo,
                                    f"SSH Weak KEX: {algo}",
                                    data['port'],
                                    Severity.LOW,
                                    data['transport']
                                ))
                                output.increase_score(20)
                    
                    for algo in kex.get('encryption_algorithms', []):
                        for check in Plugin.WEAK_ENC_ALGOS:
                            if check in algo:
                                output.add_finding(Finding(
                                    f"ssh_weak_enc",
                                    algo,
                                    f"SSH Weak Encryption: {algo}",
                                    data['port'],
                                    Severity.LOW,
                                    data['transport']
                                ))
                                output.increase_score(20)

                    for algo in kex.get('mac_algorithms', []):
                        for check in Plugin.WEAK_MAC_ALGOS:
                            if check in algo:
                                output.add_finding(Finding(
                                    f"ssh_weak_mac",
                                    algo,
                                    f"SSH Weak MAC: {algo}",
                                    data['port'],
                                    Severity.LOW,
                                    data['transport']
                                ))
                                output.increase_score(20)

    @property
    def summary(self):
        return 'Perform checks for SSH weaknesses'