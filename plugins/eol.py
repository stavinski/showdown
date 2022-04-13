
from shared import AbstractPlugin, Finding, Severity


class Plugin(AbstractPlugin):
  

    def process(self, host, output):
        for data in host['data']:
            self.check_ntlm(data, output)
            self.check_amqp(data, output)
            self.check_docker(data, output)
            self.check_db2(data, output)
            self.check_kubernetes(data, output)
            self.check_mongodb(data, output)
            self.check_mssql(data, output)
            self.check_postgres(data, output)

    def check_ntlm(self, data, output):
        if 'ntlm' in data:
            ntlm = data['ntlm']
            oses = ntlm.get('os', [])
            if 'os_build' in ntlm:
                maj, min, build = map(int, ntlm['os_build'].split('.'))  
                if (maj < 6) or (maj == 6 and min <= 1):
                    output.add_finding(Finding(
                        f"eol_os",
                        True,
                        f"EOL OS: {','.join(oses)}",
                        data['port'],
                        Severity.CRITICAL,
                        data['transport']
                    ))
                    output.increase_score(500)    

    def check_amqp(self, data, output):
        if 'amqp' in data and 'server_properties' in data['amqp']:
            server_props = data['amqp']['server_properties']
            if server_props['product'] == 'RabbitMQ':
                maj, min = map(int, server_props['version'].split('.')[:2])
                if (maj < 3) or (maj == 3 and min < 9):
                    output.add_finding(Finding(
                        f"eol_amqp",
                        True,
                        f"EOL AMQP: {server_props['product']} ({server_props['version']})",
                        data['port'],
                        Severity.CRITICAL,
                        data['transport']
                    ))
                    output.increase_score(500) 

    def check_docker(self, data, output):
        found, ver = self._get_version(data, 'Docker')
        if found:
            maj, min = map(int, ver.split('.')[:2])
            if maj < 20:
                output.add_finding(Finding(
                    f"eol_docker",
                    True,
                    f"EOL Docker: {ver}",
                    data['port'],
                    Severity.CRITICAL,
                    data['transport']
                ))
                output.increase_score(500) 

    def check_db2(self, data, output):
        if 'ibm_db2' in data and 'db2_version' in data['ibm_db2']:
            db2 = data['ibm_db2']
            ver = db2['db2_version']
            maj, min = map(int, ver.split('.')[:2])
            if maj < 12:
                output.add_finding(Finding(
                    f"eol_db2",
                    True,
                    f"EOL DB2: {ver}",
                    data['port'],
                    Severity.CRITICAL,
                    data['transport']
                ))
                output.increase_score(500) 

    def check_kubernetes(self, data, output):
        found, ver = self._get_version(data, 'Kubernetes')
        if found:
            maj, min = map(int, ver.split('.')[:2])
            if maj == 1 and min <= 20:
                output.add_finding(Finding(
                    f"eol_kubernetes",
                    True,
                    f"EOL Kubernetes: {ver}",
                    data['port'],
                    Severity.CRITICAL,
                    data['transport']
                ))
                output.increase_score(500) 

    def check_mongodb(self, data, output):
        found, ver = self._get_version(data, 'MongoDB')
        if found:
            maj, min = map(int, ver.split('.')[:2])
            if (maj < 4) or (maj <= 4 and min <= 2):
                output.add_finding(Finding(
                    f"eol_mongodb",
                    True,
                    f"EOL Mongodb: {ver}",
                    data['port'],
                    Severity.CRITICAL,
                    data['transport']
                ))
                output.increase_score(500) 

    def check_mssql(self, data, output):
        if 'mssql_ssrp' in data:
            mssql = data['mssql_ssrp']
            ver = mssql['version']
            maj, min = map(int, ver.split('.')[:2])
            if maj <= 11:
                output.add_finding(Finding(
                    f"eol_mssql",
                    True,
                    f"EOL MSSQL: {ver}",
                    data['port'],
                    Severity.CRITICAL,
                    data['transport']
                ))
                output.increase_score(500) 

    def check_postgres(self, data, output):
        found, ver = self._get_version(data, 'PostgreSQL')
        if found:
            ver_low = ver.split('-')[0].strip()
            maj, min = map(int, ver_low.split('.')[:2])
            if maj <= 10:
                output.add_finding(Finding(
                    f"eol_postgres",
                    True,
                    f"EOL Postgres: {ver}",
                    data['port'],
                    Severity.CRITICAL,
                    data['transport']
                ))
                output.increase_score(500) 

    def _get_version(self, data, name):
        if 'product' in data and data['product'] == name and 'version' in data:
            ver = data['version']
            return True, ver
        else:
            return False, None

    @property
    def summary(self):
        return 'Check for End of Life / End of Support products.'