# monitor/file_monitor.py

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler
)

import psutil
import os
import time

from utils.file_event_mapper import (
    record_file_event
)


class FileHandler(
    FileSystemEventHandler
):
    """
    Process-aware
    filesystem monitor

    Tries to attribute
    file activity to process PID.
    """

    def map_file_to_process(
        self,
        path
    ):

        try:

            for proc in psutil.process_iter(
                [
                    "pid",
                    "open_files"
                ]
            ):

                try:

                    files = (
                        proc.info.get(
                            "open_files"
                        )
                        or []
                    )

                    for f in files:

                        if (
                            f.path
                            ==
                            path
                        ):

                            return proc.pid

                except:
                    continue

        except:
            pass

        return None

    # -----------------------------------------
    # FILE EVENTS
    # -----------------------------------------
    def process_event(
        self,
        path
    ):

        pid = self.map_file_to_process(
            path
        )

        if pid:

            record_file_event(
                pid
            )

    def on_modified(
        self,
        event
    ):

        if not event.is_directory:
            self.process_event(
                event.src_path
            )

    def on_created(
        self,
        event
    ):

        if not event.is_directory:
            self.process_event(
                event.src_path
            )

    def on_deleted(
        self,
        event
    ):

        if not event.is_directory:
            self.process_event(
                event.src_path
            )


def start_file_monitor(

    paths=None
):

    if paths is None:

        paths = [

            "/tmp",
            "/var/tmp",
            "/home",

            # safe defaults
            # avoid system freeze
        ]

    observer = Observer()

    event_handler = (
        FileEventMapper()
    )

    for path in paths:

        try:

            observer.schedule(

                event_handler,

                path,

                recursive=True
            )

            print(
                f"[FILE] Monitoring: {path}"
            )

        except Exception as e:

            print(
                f"[FILE] Failed: {path}"
            )

    observer.start()

    return observer


# -----------------------------------------
# standalone test
# -----------------------------------------
if __name__ == "__main__":

    start_file_monitor(".")