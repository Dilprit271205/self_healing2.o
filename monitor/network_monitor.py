# monitor/network_monitor.py

import psutil
from collections import defaultdict


def get_network_data():
    """
    PPT + review aligned
    network collector

    Captures:
    - pid
    - connection count
    - remote destinations
    - remote ports
    - local ports
    - connection status

    Enables:
    - connection velocity
    - port spread
    - lateral movement
    - scanning detection
    """

    connections = []

    for conn in psutil.net_connections(
        kind="inet"
    ):

        try:

            pid = conn.pid

            if pid is None:
                continue

            remote_ip = None
            remote_port = None
            local_port = None

            # remote endpoint
            if conn.raddr:
                remote_ip = getattr(
                    conn.raddr,
                    "ip",
                    None
                )

                remote_port = getattr(
                    conn.raddr,
                    "port",
                    None
                )

            # local port
            if conn.laddr:
                local_port = getattr(
                    conn.laddr,
                    "port",
                    None
                )

            connections.append({

                "pid": pid,

                "status":
                    conn.status,

                "remote_ip":
                    remote_ip,

                "remote_port":
                    remote_port,

                "local_port":
                    local_port
            })

        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess
        ):
            continue

        except:
            continue

    return connections


# -----------------------------------------
# standalone test
# -----------------------------------------
if __name__ == "__main__":

    data = get_network_data()

    for conn in data[:20]:
        print(conn)