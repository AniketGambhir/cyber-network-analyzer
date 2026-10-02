from flask import Flask, render_template, request

app = Flask(__name__)


# ---------------------------------------------------------
# BUILD GRAPH
# ---------------------------------------------------------
def build_graph(devices, connections):
    graph = {device: [] for device in devices}

    for connection in connections:
        device1 = connection["device1"]
        device2 = connection["device2"]

        if device1 in graph and device2 in graph:
            graph[device1].append(device2)
            graph[device2].append(device1)

    return graph


# ---------------------------------------------------------
# BFS CONNECTIVITY
# ---------------------------------------------------------
def bfs_reachable(graph, start):
    if start not in graph:
        return set()

    visited = set()
    queue = [start]

    while queue:
        current = queue.pop(0)

        if current in visited:
            continue

        visited.add(current)

        for neighbor in graph[current]:
            if neighbor not in visited:
                queue.append(neighbor)

    return visited


# ---------------------------------------------------------
# SHORTEST PATH USING BFS
# ---------------------------------------------------------
def shortest_path(graph, start, destination):
    if start not in graph or destination not in graph:
        return []

    queue = [[start]]
    visited = set()

    while queue:
        path = queue.pop(0)
        current = path[-1]

        if current == destination:
            return path

        if current in visited:
            continue

        visited.add(current)

        for neighbor in graph[current]:
            if neighbor not in visited:
                new_path = path + [neighbor]
                queue.append(new_path)

    return []


# ---------------------------------------------------------
# ANALYZE NETWORK
# ---------------------------------------------------------
def analyze(devices, connections, start, destination):

    graph = build_graph(devices, connections)

    # Connectivity
    if devices:
        reachable = bfs_reachable(graph, devices[0])
        is_connected = len(reachable) == len(devices)
    else:
        is_connected = False

    # Degree
    degrees = {}

    for device in devices:
        degrees[device] = len(graph.get(device, []))

    # Critical device
    critical_devices = []

    if degrees:
        maximum_degree = max(degrees.values())

        if maximum_degree > 0:
            critical_devices = [
                device
                for device, degree in degrees.items()
                if degree == maximum_degree
            ]

    # Shortest path
    path = []

    if start and destination:
        path = shortest_path(graph, start, destination)

    # Security analysis
    security_warnings = []

    for connection in connections:

        device1 = connection["device1"]
        device2 = connection["device2"]
        authorized = connection["authorized"]

        if device1 not in devices or device2 not in devices:
            security_warnings.append(
                f"Unknown device found in connection: {device1} - {device2}"
            )

        if authorized.lower() != "yes":
            security_warnings.append(
                f"Unauthorized connection detected: {device1} - {device2}"
            )

    if security_warnings:
        security_status = "WARNING"
    else:
        security_status = "SAFE"

    return {
        "total_devices": len(devices),
        "total_connections": len(connections),
        "is_connected": is_connected,
        "degrees": degrees,
        "critical_devices": critical_devices,
        "path": path,
        "security_status": security_status,
        "security_warnings": security_warnings,
        "graph": graph
    }


# ---------------------------------------------------------
# HOME PAGE
# ---------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():

    result = None

    if request.method == "POST":

        devices_text = request.form.get("devices", "")
        connections_text = request.form.get("connections", "")
        start = request.form.get("start", "").strip()
        destination = request.form.get("destination", "").strip()

        # Devices
        devices = [
            device.strip()
            for device in devices_text.splitlines()
            if device.strip()
        ]

        # Connections
        connections = []

        for line in connections_text.splitlines():

            line = line.strip()

            if not line:
                continue

            parts = [part.strip() for part in line.split(",")]

            if len(parts) >= 2:

                device1 = parts[0]
                device2 = parts[1]

                authorized = "yes"

                if len(parts) >= 3:
                    authorized = parts[2]

                connections.append({
                    "device1": device1,
                    "device2": device2,
                    "authorized": authorized
                })

        result = analyze(
            devices,
            connections,
            start,
            destination
        )

    return render_template(
        "index.html",
        result=result
    )


# ---------------------------------------------------------
# RUN SERVER
# ---------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)