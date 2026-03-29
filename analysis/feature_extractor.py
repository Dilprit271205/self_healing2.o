def extract_features(process, connection_map, file_map):
    pid = process["pid"]

    return {
        "pid": pid,
        "name": process["name"],
        "cpu": process["cpu"],
        "memory": process["memory"],
        "connections": connection_map.get(pid, 0),
        "file_events": file_map.get(pid, 0)
    }