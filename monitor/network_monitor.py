import psutil
from collections import defaultdict, deque


class NetworkMonitor:

    def __init__(self):

        self.connection_history = defaultdict(
            lambda: deque(maxlen=10)
        )

    # =====================================
    # NETWORK INTELLIGENCE
    # =====================================
    def get_network_data(self):

        network_data = {}

        try:

            for proc in psutil.process_iter(

                [
                    "pid",
                    "name"
                ]
            ):

                try:

                    pid = proc.info["pid"]

                    # --------------------------------
                    # SAFE CONNECTION API
                    # psutil >= 6 compatible
                    # --------------------------------
                    connections = (
                        proc.net_connections()
                    )

                    active_connections = len(
                        connections
                    )

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

                    # --------------------------------
                    # CONNECTION VELOCITY
                    # --------------------------------
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

                    # --------------------------------
                    # PORT SPREAD
                    # --------------------------------
                    port_spread = len(
                        unique_ports
                    )

                    # --------------------------------
                    # SCANNING DETECTION
                    # --------------------------------
                    scanning_score = 0

                    if port_spread > 20:
                        scanning_score += 0.4

                    if connection_velocity > 10:
                        scanning_score += 0.3

                    if len(remote_ips) > 15:
                        scanning_score += 0.3

                    scanning_detected = (
                        scanning_score >= 0.5
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
                            len(remote_ips),

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

        return network_data