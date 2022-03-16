import importlib
import pkgutil
import plugins


class PluginRegistry(object):
    
    available = [name for finder, name, ispkg in pkgutil.iter_modules(plugins.__path__)]

    def __init__(self):
        self.loaded = { plugin: importlib.import_module(f"plugins.{plugin}",'plugins').Plugin() for plugin in PluginRegistry.available}

    def retrieve_plugins(self, names):
        for name in names:
            yield self.loaded[name]

    def list(self):
        return ((name, plugin.summary) for name, plugin in self.loaded.items())
