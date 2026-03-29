from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

from utils.file_event_mapper import record_file_event


class FileHandler(FileSystemEventHandler):

    def on_modified(self, event):
        record_file_event(0)

    def on_created(self, event):
        record_file_event(0)

    def on_deleted(self, event):
        record_file_event(0)


def start_file_monitor(path="."):
    observer = Observer()
    handler = FileHandler()

    observer.schedule(handler, path=path, recursive=True)
    observer.start()

    print("📂 File monitoring started...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()