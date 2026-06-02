# ==========================================
# CONNECTION MAP
# network monitor compatible
# ==========================================
def map_connections(

    network_data
):

    conn_map = {}

    try:

        for (
            pid,
            info
        ) in network_data.items():

            conn_map[
                pid
            ] = {

                "connections":
                    info.get(
                        "connections",
                        0
                    ),

                "connection_velocity":
                    info.get(
                        "connection_velocity",
                        0
                    ),

                "port_spread":
                    info.get(
                        "port_spread",
                        0
                    ),

                "remote_ips":
                    info.get(
                        "remote_ips",
                        0
                    ),

                "loopback_connections":
                    info.get(
                        "loopback_connections",
                        0
                    ),

                "network_event_count":
                    info.get(
                        "network_event_count",
                        0
                    ),

                "loopback_event_count":
                    info.get(
                        "loopback_event_count",
                        0
                    ),

                "connection_rate":
                    info.get(
                        "connection_rate",
                        0
                    ),

                "loopback_connection_rate":
                    info.get(
                        "loopback_connection_rate",
                        0
                    ),

                "scanning_score":
                    info.get(
                        "scanning_score",
                        0
                    ),

                "scanning_detected":
                    info.get(
                        "scanning_detected",
                        False
                    )
            }

    except Exception as e:

        print(
            f"Connection mapper error: {e}"
        )

    return conn_map
