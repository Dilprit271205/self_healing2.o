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

        self.connection_event_history = defaultdict(

            lambda: deque(
                maxlen=30
            )
        )

        # ---------------------------------
        # CACHE
        # avoids expensive scans
        # every loop
        # ---------------------------------
        self.last_scan = 0

        self.cached_network_data = {}

        try:
            self.scan_interval = float(
                __import__("os").getenv(
                    "SELF_HEALING_NETWORK_SCAN_INTERVAL",
                    "0.25"
                )
            )
        except Exception:
            self.scan_interval = 0.25

        try:
            self.event_window_seconds = float(
                __import__("os").getenv(
                    "SELF_HEALING_NETWORK_EVENT_WINDOW",
                    "12"
                )
            )
        except Exception:
            self.event_window_seconds = 12


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

            pid_stats = defaultdict(
                lambda: {
                    "connections": 0,
                    "ports": set(),
                    "remote_ips": set(),
                    "loopback_connections": 0
                }
            )

            for conn in psutil.net_connections(kind="inet"):

                pid = getattr(conn, "pid", None)

                if not pid:
                    continue

                pid_stats[pid]["connections"] += 1

                if conn.laddr:
                    pid_stats[pid]["ports"].add(
                        conn.laddr.port
                    )

                if conn.raddr:
                    pid_stats[pid]["remote_ips"].add(
                        conn.raddr.ip
                    )

                    if conn.raddr.ip in {
                        "127.0.0.1",
                        "::1"
                    }:
                        pid_stats[pid]["loopback_connections"] += 1

                if conn.laddr and conn.laddr.ip in {
                    "127.0.0.1",
                    "::1"
                }:
                    pid_stats[pid]["loopback_connections"] += 1

            for pid, stats in pid_stats.items():

                active_connections = stats["connections"]

                if active_connections == 0:
                    continue

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

                port_spread = len(
                    stats["ports"]
                )

                remote_ips = len(
                    stats["remote_ips"]
                )

                loopback_connections = stats[
                    "loopback_connections"
                ]

                event_history = self.connection_event_history[
                    pid
                ]

                event_history.append(
                    {
                        "time": current_time,
                        "connections": active_connections,
                        "loopback_connections":
                            loopback_connections,
                        "port_spread": port_spread,
                        "remote_ips": remote_ips
                    }
                )

                while (
                    event_history
                    and current_time
                    - event_history[0]["time"]
                    > self.event_window_seconds
                ):
                    event_history.popleft()

                network_event_count = sum(
                    item.get(
                        "connections",
                        0
                    )
                    for item in event_history
                )

                loopback_event_count = sum(
                    item.get(
                        "loopback_connections",
                        0
                    )
                    for item in event_history
                )

                connection_rate = (
                    network_event_count
                    /
                    max(
                        self.event_window_seconds,
                        1
                    )
                )

                loopback_connection_rate = (
                    loopback_event_count
                    /
                    max(
                        self.event_window_seconds,
                        1
                    )
                )

                scanning_score = 0

                if (
                    port_spread
                    > 20
                ):
                    scanning_score += 0.4

                if (
                    connection_velocity
                    > 10
                    or connection_rate
                    > 8
                ):
                    scanning_score += 0.3

                if (
                    remote_ips
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
                        remote_ips,

                    "loopback_connections":
                        loopback_connections,

                    "network_event_count":
                        network_event_count,

                    "loopback_event_count":
                        loopback_event_count,

                    "connection_rate":
                        round(
                            connection_rate,
                            2
                        ),

                    "loopback_connection_rate":
                        round(
                            loopback_connection_rate,
                            2
                        ),

                    "scanning_score":
                        round(
                            scanning_score,
                            2
                        ),

                    "scanning_detected":
                        scanning_detected
                }

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
