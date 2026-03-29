def map_connections(network_data):
    conn_map = {}

    for conn in network_data:
        pid = conn.get("pid")

        if pid:
            conn_map[pid] = conn_map.get(pid, 0) + 1

    return conn_map