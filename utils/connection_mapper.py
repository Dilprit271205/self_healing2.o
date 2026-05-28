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