
from datetime import datetime, timedelta
from shared import AbstractPlugin, Finding, Severity


class Plugin(AbstractPlugin):

    _PROTOS = {
        'SSLv2': Severity.HIGH,
        'SSLv3': Severity.HIGH,
        'TLSv1': Severity.MEDIUM,
        'TLSv1.1': Severity.LOW
    }

    _CIPHERS_INSECURE = [
        'ADH-DES-CBC3-SHA',
        'ADH-AES128-SHA',
        'ADH-AES128-SHA256',
        'ADH-AES128-GCM-SHA256',
        'ADH-AES256-SHA',
        'ADH-AES256-SHA256',
        'ADH-AES256-GCM-SHA384',
        'ADH-CAMELLIA128-SHA',
        'ADH-CAMELLIA128-SHA256',
        'ADH-CAMELLIA256-SHA',
        'ADH-CAMELLIA256-SHA256',
        'ADH-SEED-SHA',
        'DHE-PSK-NULL-SHA',
        'DHE-PSK-NULL-SHA256',
        'DHE-PSK-NULL-SHA384',
        'AECDH-DES-CBC3-SHA',
        'AECDH-AES128-SHA',
        'AECDH-AES256-SHA',
        'AECDH-NULL-SHA',
        'ECDHE-ECDSA-NULL-SHA',
        'ECDHE-PSK-NULL-SHA',
        'ECDHE-PSK-NULL-SHA256',
        'ECDHE-PSK-NULL-SHA384',
        'ECDHE-RSA-NULL-SHA',
        'PSK-NULL-SHA',
        'PSK-NULL-SHA256',
        'PSK-NULL-SHA384',
        'RSA-PSK-NULL-SHA',
        'RSA-PSK-NULL-SHA256',
        'RSA-PSK-NULL-SHA384',
        'NULL-MD5',
        'NULL-SHA',
        'NULL-SHA256'
    ]

    _CIPHERS_WEAK = [
        'DHE-DSS-DES-CBC3-SHA',
        'DHE-DSS-AES128-SHA',
        'DHE-DSS-AES128-SHA256',
        'DHE-DSS-AES256-SHA',
        'DHE-DSS-AES256-SHA256',
        'DHE-DSS-CAMELLIA128-SHA',
        'DHE-DSS-CAMELLIA128-SHA256',
        'DHE-DSS-CAMELLIA256-SHA',
        'DHE-DSS-CAMELLIA256-SHA256',
        'DHE-DSS-SEED-SHA',
        'DHE-PSK-3DES-EDE-CBC-SHA',
        'DHE-PSK-AES128-CBC-SHA',
        'DHE-PSK-AES128-CBC-SHA256',
        'DHE-PSK-AES256-CBC-SHA',
        'DHE-PSK-AES256-CBC-SHA384',
        'DHE-PSK-CAMELLIA128-SHA256',
        'DHE-PSK-CAMELLIA256-SHA384',
        'DHE-RSA-DES-CBC3-SHA',
        'DHE-RSA-AES128-SHA',
        'DHE-RSA-AES128-SHA256',
        'DHE-RSA-AES256-SHA',
        'DHE-RSA-AES256-SHA256',
        'DHE-RSA-CAMELLIA128-SHA',
        'DHE-RSA-CAMELLIA128-SHA256',
        'DHE-RSA-CAMELLIA256-SHA',
        'DHE-RSA-CAMELLIA256-SHA256',
        'DHE-RSA-SEED-SHA',
        'ECDHE-ECDSA-DES-CBC3-SHA',
        'ECDHE-ECDSA-AES128-SHA',
        'ECDHE-ECDSA-AES128-SHA256',
        'ECDHE-ECDSA-AES256-SHA',
        'ECDHE-ECDSA-AES256-SHA384',
        'ECDHE-ECDSA-CAMELLIA128-SHA256',
        'ECDHE-ECDSA-CAMELLIA256-SHA384',
        'ECDHE-PSK-3DES-EDE-CBC-SHA',
        'ECDHE-PSK-AES128-CBC-SHA',
        'ECDHE-PSK-AES128-CBC-SHA256',
        'ECDHE-PSK-AES256-CBC-SHA',
        'ECDHE-PSK-AES256-CBC-SHA384',
        'ECDHE-PSK-CAMELLIA128-SHA256',
        'ECDHE-PSK-CAMELLIA256-SHA384',
        'ECDHE-RSA-DES-CBC3-SHA',
        'ECDHE-RSA-AES128-SHA',
        'ECDHE-RSA-AES128-SHA256',
        'ECDHE-RSA-AES256-SHA',
        'ECDHE-RSA-AES256-SHA384',
        'ECDHE-RSA-CAMELLIA128-SHA256',
        'ECDHE-RSA-CAMELLIA256-SHA384',
        'PSK-3DES-EDE-CBC-SHA',
        'PSK-AES128-CBC-SHA',
        'PSK-AES128-CBC-SHA256',
        'PSK-AES128-CCM',
        'PSK-AES128-CCM8',
        'PSK-AES128-GCM-SHA256',
        'PSK-AES256-CBC-SHA',
        'PSK-AES256-CBC-SHA384',
        'PSK-AES256-CCM',
        'PSK-AES256-CCM8',
        'PSK-AES256-GCM-SHA384',
        'PSK-CAMELLIA128-SHA256',
        'PSK-CAMELLIA256-SHA384',
        'PSK-CHACHA20-POLY1305',
        'RSA-PSK-3DES-EDE-CBC-SHA',
        'RSA-PSK-AES128-CBC-SHA',
        'RSA-PSK-AES128-CBC-SHA256',
        'RSA-PSK-AES128-GCM-SHA256',
        'RSA-PSK-AES256-CBC-SHA',
        'RSA-PSK-AES256-CBC-SHA384',
        'RSA-PSK-AES256-GCM-SHA384',
        'RSA-PSK-CAMELLIA128-SHA256',
        'RSA-PSK-CAMELLIA256-SHA384',
        'RSA-PSK-CHACHA20-POLY1305',
        'DES-CBC3-SHA',
        'AES128-SHA',
        'AES128-SHA256',
        'AES128-CCM',
        'AES128-CCM8',
        'AES128-GCM-SHA256',
        'AES256-SHA',
        'AES256-SHA256',
        'AES256-CCM',
        'AES256-CCM8',
        'AES256-GCM-SHA384',
        'CAMELLIA128-SHA',
        'CAMELLIA128-SHA256',
        'CAMELLIA256-SHA',
        'CAMELLIA256-SHA256',
        'IDEA-CBC-SHA',
        'SEED-SHA',
        'SRP-DSS-3DES-EDE-CBC-SHA',
        'SRP-DSS-AES-128-CBC-SHA',
        'SRP-DSS-AES-256-CBC-SHA',
        'SRP-RSA-3DES-EDE-CBC-SHA',
        'SRP-RSA-AES-128-CBC-SHA',
        'SRP-RSA-AES-256-CBC-SHA',
        'SRP-3DES-EDE-CBC-SHA',
        'SRP-AES-128-CBC-SHA',
        'SRP-AES-256-CBC-SHA'
    ]

    def process(self, host, output):
        for data in host['data']:
            if not 'ssl' in data:
                continue

            ssl = data['ssl']
            self.check_protos(output, data, ssl)
            self.check_certs(output, data, ssl)
            self.check_ciphers(output, data, ssl)

    def check_protos(self, output, data, ssl):
        for version in ssl['versions']:
                if version in Plugin._PROTOS:
                    output.add_finding(Finding(
                        f"protocol_weak_{version}",
                        version,
                        f"Weak protocol: {version}",
                        data['port'],
                        Plugin._PROTOS[version],
                        data['transport']
                    ))
                    output.increase_score(Plugin._PROTOS[version].value * 100)

    def check_certs(self, output, data, ssl):
        cert = ssl['cert']
        trust = ssl.get('trust', None)
        signed_algo = cert.get('sig_algo', None)
        expired = cert.get('expired', False)
        expires = cert.get('expires', None)
        pub_key = cert.get('pubkey', None)
        subject = cert.get('subject', None)
        extensions = cert.get('extensions', [])
        if signed_algo == 'sha1WithRSAEncryption':
            output.add_finding(Finding(
                        f"cert_sha1_signing",
                        signed_algo,
                        f"SHA1 signed cert",
                        data['port'],
                        Severity.MEDIUM,
                        data['transport']
                    ))
            output.increase_score(50)

        if expired:
            output.add_finding(Finding(
                        f"cert_expired",
                        signed_algo,
                        f"Expired cert",
                        data['port'],
                        Severity.HIGH,
                        data['transport']
                    ))
            output.increase_score(200)

        if not expired and expires:
            expires_date = datetime.strptime(expires, '%Y%m%d%H%M%SZ')
            three_mths = datetime.utcnow() + timedelta(weeks=12)
            if expires_date < three_mths:
                output.add_finding(Finding(
                        f"cert_expires_soon",
                        expires_date,
                        f"Cert expires soon: {expires_date:%Y-%m-%d %H:%M}",
                        data['port'],
                        Severity.LOW,
                        data['transport']
                    ))
                output.increase_score(50)

        if pub_key and pub_key['type'] == 'rsa':
            if pub_key['bits'] <= 1024:
                output.add_finding(Finding(
                        f"cert_rsa_pub_keysize",
                        pub_key['bits'],
                        f"Cert uses low public key size: {pub_key['bits']}",
                        data['port'],
                        Severity.LOW,
                        data['transport']
                    ))
                output.increase_score(50)
        
        if subject and '*.' in subject['CN']:
                output.add_finding(Finding(
                        f"cert_wildcard_cn",
                        subject['CN'],
                        f"Wildcard cert CN: {subject['CN']}",
                        data['port'],
                        Severity.LOW,
                        data['transport']
                    ))
                output.increase_score(50)
        
        found = [extension['data'] for extension in extensions if extension['name'] == 'subjectAltName']
        if found:
            alt_names = found[0]

            if '*.' in alt_names:
                output.add_finding(Finding(
                            f"cert_wildcard_altnames",
                            alt_names,
                            f"Wildcard cert alt names: {alt_names}",
                            data['port'],
                            Severity.LOW,
                            data['transport']
                        ))
                output.increase_score(50)
        
        if trust and trust['revoked']:
            output.add_finding(Finding(
                        f"cert_revoked",
                        trust['revoked'],
                        "Cert revoked",
                        data['port'],
                        Severity.HIGH,
                        data['transport']
                    ))
            output.increase_score(200)

    def check_ciphers(self, output, data, ssl):
        cipher = ssl.get('cipher', None)
        if not cipher:
            return

        name = cipher['name']
        if name in Plugin._CIPHERS_INSECURE:
            output.add_finding(Finding(
                    "cipher_insecure",
                    name,
                    f"Insecure cipher: {name}",
                    data['port'],
                    Severity.HIGH,
                    data['transport']
                ))
            output.increase_score(200)

        if name in Plugin._CIPHERS_WEAK:
            output.add_finding(Finding(
                    "cipher_weak",
                    name,
                    f"Weak cipher: {name}",
                    data['port'],
                    Severity.MEDIUM,
                    data['transport']
                ))
            output.increase_score(100)

    def summary(self):
        return 'Findings related to SSL/TLS issues such as legacy protocols and weak ciphers.'    