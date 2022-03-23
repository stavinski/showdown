
from shared import AbstractPlugin, Finding


class Plugin(AbstractPlugin):

    def process(self, host, output):
        
        providers = set()
        services = set()
        regions = set()

        for data in host['data']:
            if not 'cloud' in data:
                continue

            cloud = data['cloud']
            provider = cloud['provider']
            service = cloud['service']
            region = cloud['region']
            
            if provider not in providers:
                providers.add(provider)

            if service not in services:
                services.add(service)
            
            if region not in regions:
                regions.add(region)
        
        if providers:
            output.add_finding(Finding(
                        'cloud_providers',
                        providers,
                        f"Cloud Providers: {','.join(providers)}"
                    ))

        if services:
            output.add_finding(Finding(
                        'cloud_services',
                        services,
                        f"Cloud services: {','.join(services)}"
                    ))

        if regions:
            output.add_finding(Finding(
                        'cloud_regions',
                        regions,
                        f"Cloud regions: {','.join(regions)}"
                    ))


    @property
    def summary(self):
        return 'Cloud details associated with services on host.'