from shared import AbstractPlugin, Finding, Severity


class Plugin(AbstractPlugin):

    def process(self, host, output):
        for data in host['data']:
            self._check_cassandra(data, output)
            self._check_couchdb(data, output)
            self._check_db2(data, output)
            self._check_influxdb(data, output)
            self._check_mongodb(data, output)
            self._check_redis(data, output)
            self._check_cockroachdb(data, output)        

    def _check_cassandra(self, data, output):
        if 'cassandra' in data:
            cassandra = data['cassandra']
            output.add_finding(Finding(
                        f"cassandra_exposed",
                        cassandra['name'],
                        f"{cassandra['name']} ({cassandra['version']})",
                        data['port'],
                        Severity.INFO,
                        data['transport']
                    ))

            if 'keyspaces' in cassandra:
                output.add_finding(Finding(
                            f"cassandra_keyspaces",
                            cassandra['name'],
                            f"Cassandra keyspaces",
                            data['port'],
                            Severity.INFO,
                            data['transport'],
                            items=cassandra['keyspaces']
                        ))

    def _check_couchdb(self, data, output):
        if 'couchdb' in data:
            couchdb = data['couchdb']
            if 'couchdb' in couchdb:
                output.add_finding(Finding(
                            f"couchdb_exposed",
                            couchdb['couchdb'],
                            f"Couch DB exposed: {couchdb['couchdb']} ({couchdb['version']})",
                            data['port'],
                            Severity.INFO,
                            data['transport']
                        ))
                if 'dbs' in couchdb:
                    output.add_finding(Finding(
                                f"couchdb_databases",
                                couchdb['couchdb'],
                                f"Couchdb Databases",
                                data['port'],
                                Severity.INFO,
                                data['transport'],
                                items=couchdb['dbs']
                            ))
            
    def _check_db2(self, data, output):
        if 'ibm_db2' in data:
            db2 = data['ibm_db2']
            output.add_finding(Finding(
                            f"DB2_exposed",
                            db2['instance_name'],
                            f"DB2 DB exposed: {db2['instance_name']} ({db2['db2_version']})",
                            data['port'],
                            Severity.INFO,
                            data['transport']
                        ))

    def _check_influxdb(self, data, output):
        if 'influxdb' in data:
            influxdb = data['influxdb']
            output.add_finding(Finding(
                            f"influxdb_exposed",
                            "InfluxDB",
                            f"Influx DB exposed: {influxdb['version']}",
                            data['port'],
                            Severity.INFO,
                            data['transport']
                        ))
            if 'databases' in influxdb:
                output.add_finding(Finding(
                                f"influxdb_databases",
                                'Influxdb',
                                f"Influxdb Databases",
                                data['port'],
                                Severity.INFO,
                                data['transport'],
                                items=influxdb['databases']
                            ))

    def _check_mongodb(self, data, output):
        if 'mongodb' in data:
            mongodb = data['mongodb']
            version = ""
            if 'serverStatus' in mongodb and 'version' in mongodb['serverStatus']:
                version = mongodb['serverStatus']['version']

            output.add_finding(Finding(
                            f"mongodb_exposed",
                            "MongoDB",
                            f"MongoDB DB exposed ({version})",
                            data['port'],
                            Severity.INFO,
                            data['transport']
                        ))
            
            if 'listDatabases' in mongodb:
                listDatabases = mongodb['listDatabases']
                dbs = [db['name'] for db in listDatabases['databases']]
                output.add_finding(Finding(
                                f"mongodb_databases",
                                'MongoDB',
                                f"MongoDB Databases",
                                data['port'],
                                Severity.INFO,
                                data['transport'],
                                items=dbs
                            ))
            
            if not mongodb['authentication']:
                output.add_finding(Finding(
                            f"mongodb_no_auth",
                            True,
                            f"MongoDB With No Auth",
                            data['port'],
                            Severity.HIGH,
                            data['transport']
                        ))
                output.increase_score(200)

    def _check_redis(self, data, output):
        if 'redis' in data:
            redis = data['redis']
            version = ''
            if 'server' in redis:
                server = redis['server']
                version = server.get('redis_version', '')
                output.add_finding(Finding(
                            f"redis_exposed",
                            "Redis",
                            f"Redis DB exposed ({version})",
                            data['port'],
                            Severity.INFO,
                            data['transport']
                        ))
            
            if 'keys' in redis:
                output.add_finding(Finding(
                                f"redis_keys",
                                'Redis',
                                f"Redis keys",
                                data['port'],
                                Severity.INFO,
                                data['transport'],
                                items=redis['keys']['data']
                            ))

    def _check_cockroachdb(self, data, output):
        if 'cockroachdb' in data:
            cockroachdb = data['cockroachdb']
            output.add_finding(Finding(
                            f"cockroachdb_exposed",
                            "Cockroachdb",
                            f"Cockroach DB exposed ({cockroachdb['version']})",
                            data['port'],
                            Severity.INFO,
                            data['transport']
                        ))

            if 'experimental_user_login' in cockroachdb and cockroachdb['experimental_user_login']:
                output.add_finding(Finding(
                            f"cockroachdb_no_auth",
                            True,
                            f"Cockroachdb With No Auth",
                            data['port'],
                            Severity.HIGH,
                            data['transport']
                        ))
                output.increase_score(200)


    @property
    def summary(self):
        return 'Details of DBs found like MongoDB, Redis etc...'
