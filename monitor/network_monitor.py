import psutil

def get_network_data():
    connections = []

    for conn in psutil.net_connections(kind='inet'):
        try:
            connections.append({
                "pid": conn.pid,
                "status": conn.status
            })
        except:
            continue

    return connections