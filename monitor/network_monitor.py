import psutil
import time

from collections import (
    defaultdict,
    deque
)


class NetworkMonitor:

    def __init__(self):

        # ---------------------------------
        # HISTORY BUFFER
        # velocity tracking
        # ---------------------------------
        self.connection_history = defaultdict(

            lambda: deque(
                maxlen=10
            )
        )

        # ---------------------------------
        # CACHE
        # avoids expensive scans
        # every loop
        # ---------------------------------
        self.last_scan = 0

        self.cached_network_data = {}

        self.scan_interval = 8


    # =====================================
    # NETWORK INTELLIGENCE
    # stable version
    # =====================================
    def get_network_data(self):

        current_time = time.time()

        # ---------------------------------
        # CACHE THROTTLE
        # avoids CPU overload
        # ---------------------------------
        if (

            current_time
            -
            self.last_scan

            <

            self.scan_interval
        ):

            return (
                self.cached_network_data
            )

        network_data = {}

        try:

            for proc in psutil.process_iter(

                [
                    "pid",
                    "name"
                ]
            ):

                try:

                    pid = (
                        proc.info[
                            "pid"
                        ]
                    )

                    process_name = (
                        proc.info.get(
                            "name",
                            ""
                        ).lower()
                    )

                    # ---------------------------------
                    # SAFE PROCESS FILTER
                    # skip OS critical
                    # ---------------------------------
                    ignored = [

                        "systemd",
                        "dbus",
                        "kworker",
                        "ksoftirqd",
                        "migration",
                        "rcu",

                        "xorg",
                        "gnome-shell",

                        "chrome",
                        "firefox",

                        "code"
                    ]

                    if any(

                        x
                        in
                        process_name

                        for x in ignored
                    ):

                        continue

                    # ---------------------------------
                    # CPU FILTER
                    # skip sleeping/background
                    # processes
                    # ---------------------------------
                    try:

                        cpu = (
                            proc.cpu_percent()
                        )

                        if cpu < 0.5:

                            continue

                    except:

                        continue

                    # ---------------------------------
                    # SAFE CONNECTION API
                    # psutil >= 6 compatible
                    # ---------------------------------
                    try:

                        connections = (
                            proc.net_connections()
                        )

                    except (

                        psutil.AccessDenied,
                        psutil.NoSuchProcess,
                        AttributeError
                    ):

                        continue

                    active_connections = len(
                        connections
                    )

                    # skip dead network
                    if (
                        active_connections
                        == 0
                    ):
                        continue

                    unique_ports = set()

                    remote_ips = set()

                    for conn in connections:

                        try:

                            if conn.laddr:

                                unique_ports.add(

                                    conn.laddr.port
                                )

                            if conn.raddr:

                                remote_ips.add(

                                    conn.raddr.ip
                                )

                        except:
                            continue

                    # ---------------------------------
                    # CONNECTION VELOCITY
                    # reviewer aligned
                    # ---------------------------------
                    history = (

                        self.connection_history[
                            pid
                        ]
                    )

                    prev_connections = (

                        history[-1]
                        if history
                        else 0
                    )

                    connection_velocity = (

                        active_connections
                        -
                        prev_connections
                    )

                    history.append(
                        active_connections
                    )

                    # ---------------------------------
                    # PORT SPREAD
                    # reviewer issue
                    # ---------------------------------
                    port_spread = len(
                        unique_ports
                    )

                    # ---------------------------------
                    # SCANNING DETECTION
                    # reviewer issue
                    # ---------------------------------
                    scanning_score = 0

                    if (
                        port_spread
                        > 20
                    ):
                        scanning_score += 0.4

                    if (
                        connection_velocity
                        > 10
                    ):
                        scanning_score += 0.3

                    if (
                        len(
                            remote_ips
                        )
                        > 15
                    ):
                        scanning_score += 0.3

                    scanning_detected = (

                        scanning_score
                        >= 0.5
                    )

                    network_data[
                        pid
                    ] = {

                        "connections":
                            active_connections,

                        "connection_velocity":
                            connection_velocity,

                        "port_spread":
                            port_spread,

                        "remote_ips":
                            len(
                                remote_ips
                            ),

                        "scanning_score":
                            round(
                                scanning_score,
                                2
                            ),

                        "scanning_detected":
                            scanning_detected
                    }

                except (

                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    AttributeError

                ):

                    continue

        except Exception as e:

            print(
                f"Network monitor error: {e}"
            )

        # ---------------------------------
        # CACHE UPDATE
        # ---------------------------------
        self.cached_network_data = (
            network_data
        )

        self.last_scan = (
            current_time
        )

        return network_data