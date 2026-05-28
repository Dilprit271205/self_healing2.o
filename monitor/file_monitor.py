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
    Stable process-aware
    filesystem monitor.

    Maps file activity
    to process PID.
    """

    def __init__(self):

        # -------------------------
        # throttle repeated scans
        # avoids CPU spikes
        # -------------------------
        self.last_scan = {}

        self.cooldown = 1.5

    # =====================================
    # FILE -> PROCESS MAPPING
    # =====================================
    def map_file_to_process(
        self,
        path
    ):

        current_time = (
            time.time()
        )

        # -------------------------
        # cooldown
        # prevents spam scans
        # -------------------------
        last = self.last_scan.get(
            path,
            0
        )

        if (
            current_time
            - last
            <
            self.cooldown
        ):

            return None

        self.last_scan[
            path
        ] = current_time

        try:

            for proc in psutil.process_iter(

                [
                    "pid",
                    "open_files",
                    "name"
                ]
            ):

                try:

                    files = (

                        proc.info.get(
                            "open_files"
                        )
                        or []
                    )

                    if not files:
                        continue

                    for f in files:

                        try:

                            if (
                                f.path
                                ==
                                path
                            ):

                                return (
                                    proc.pid
                                )

                        except:
                            continue

                except (

                    psutil.NoSuchProcess,
                    psutil.AccessDenied
                ):

                    continue

        except Exception:

            pass

        return None

    # =====================================
    # FILE EVENTS
    # =====================================
    def process_event(
        self,
        path
    ):

        pid = (
            self.map_file_to_process(
                path
            )
        )

        if pid:

            record_file_event(
                pid
            )

    def on_modified(
        self,
        event
    ):

        if (
            not
            event.is_directory
        ):

            self.process_event(
                event.src_path
            )

    def on_created(
        self,
        event
    ):

        if (
            not
            event.is_directory
        ):

            self.process_event(
                event.src_path
            )

    def on_deleted(
        self,
        event
    ):

        if (
            not
            event.is_directory
        ):

            self.process_event(
                event.src_path
            )


# =====================================
# FILE MONITOR
# =====================================
def start_file_monitor(

    paths=None
):

    # ---------------------------------
    # SAFE DEFAULT PATHS
    # ---------------------------------
    if paths is None:

        paths = [

            "/home/suyash-anand/Downloads",

            "/tmp",

            "/var/tmp"
        ]

    # ---------------------------------
    # PATH VALIDATION
    # ---------------------------------
    safe_paths = []

    for path in paths:

        if os.path.exists(
            path
        ):

            safe_paths.append(
                path
            )

        else:

            print(
                f"[FILE] SKIP: {path}"
            )

    observer = Observer()

    event_handler = (
        FileHandler()
    )

    # ---------------------------------
    # SAFE WATCH SETUP
    # ---------------------------------
    for path in safe_paths:

        try:

            observer.schedule(

                event_handler,

                path,

                # IMPORTANT
                # prevents inotify crash
                recursive=False
            )

            print(
                f"[FILE] Monitoring: {path}"
            )

        except Exception as e:

            print(
                f"[FILE] Failed: "
                f"{path} | {e}"
            )

    observer.start()

    print(
        "📁 File monitor started"
    )

    return observer


# =====================================
# STANDALONE TEST
# =====================================
if __name__ == "__main__":

    observer = (
        start_file_monitor()
    )

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

    observer.join()