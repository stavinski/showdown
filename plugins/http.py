
from shared import AbstractPlugin, Finding, Severity


class Plugin(AbstractPlugin):
    
    _KEYWORDS = [
        'ConsumerKey',
        'ConsumerSecret',
        'DB_USERNAME',
        'HEROKU_API_KEY',
        'HOMEBREW_GITHUB_API_TOKEN',
        'JEKYLL_GITHUB_TOKEN',
        'PT_TOKEN',
        'SESSION_TOKEN',
        'SF_USERNAME',
        'SLACK_BOT_TOKEN',
        'access-token',
        'access_token',
        'access_token_secret',
        'accesstoken',
        'admin',
        'api-key',
        'api_key',
        'api_secret_key',
        'api_token',
        'auth_token',
        'authkey',
        'authorization',
        'authorization_key',
        'authorization_token',
        'authtoken',
        'aws_access_key_id',
        'aws_secret_access_key',
        'bearer',
        'bot_access_token',
        'bucket',
        'client-secret',
        'client_id',
        'client_key',
        'client_secret',
        'clientsecret',
        'consumer_key',
        'consumer_secret',
        'dbpasswd',
        'email',
        'encryption-key',
        'encryption_key',
        'encryptionkey',
        'id_dsa',
        'irc_pass',
        'key',
        'oauth_token',
        'pass',
        'password',
        'private_key',
        'private-key',
        'privatekey',
        'secret',
        'secret-key',
        'secret_key',
        'secret_token',
        'secretkey',
        'secretkey',
        'session_key',
        'session_secret',
        'slack_api_token',
        'slack_secret_token',
        'slack_token',
        'ssh-key',
        'ssh_key',
        'sshkey',
        'token',
        'username',
        'xoxa-2',
        'xoxr'
    ]

    def process(self, host, output):
        for data in host['data']:
            if not 'http' in data:
                continue

            http = data['http']
            robots = http.get('robots', None)
            if robots and 'Disallow:' in robots:
                output.add_finding(Finding(
                    'robots_txt',
                    robots,
                    f"Disallows in robots.txt:",
                    data['port'],
                    Severity.LOW,
                    data['transport'],
                    items=[line.replace('Disallow:', '') for line in robots.split('\n') if line.find('Disallow:') != -1]
                ))
                output.increase_score(50)

            html = http.get('html', None)
            if html:
                for keyword in Plugin._KEYWORDS:
                    if keyword in html.lower():
                        output.add_finding(Finding(
                            f"html_keyword_{keyword}",
                            keyword,
                            f"Found keyword in HTML: {keyword}",
                            data['port'],
                            Severity.HIGH,
                            data['transport']
                        ))
                        output.increase_score(200)

            title = http.get('title', None)
            if title and 'index of' in title.lower():
                output.add_finding(Finding(
                            f"http_dir_listing",
                            title,
                            f"Found directory listing: {title}",
                            data['port'],
                            Severity.HIGH,
                            data['transport']
                        ))
                output.increase_score(200)

    @property
    def summary(self):
        return 'Checks HTTP services to try and discover interesting findings such as robots.txt entries, keywords in HTML etc...'
