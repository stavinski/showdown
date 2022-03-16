from queue import Queue
from threading import Lock, Thread
from time import sleep


class Downloader(object):
    
    def __init__(self, api, thread_count, ips, delay=1):
        self.lock = Lock()
        self.api = api
        self.thread_count = thread_count
        self.delay = delay
        self.ips = ips
        self.queue = Queue(len(ips))
        self.threads = []
        self.results = []

    def download(self, processed_callback=lambda _: None):
        for count in range(0, self.thread_count):
            thread = Thread(target=self._download_host, name=f'downloader-{count}', args=(processed_callback,))
            thread.setDaemon(True)
            thread.start()

        for ip in self.ips:
            self.queue.put(ip)
            sleep(self.delay)  # shodan API is rate limited so requires a delay between reqs

        self.queue.join()
        return self.results

    def _download_host(self, processed_callback):
        while True:
            ip = self.queue.get()
            try:
                success, ip, result = self.api.host(ip)
                if success:
                    self.results.append(result)
                    with self.lock:
                        processed_callback(True)
                else:
                    with self.lock:
                        processed_callback(False)
            finally:
                self.queue.task_done()
