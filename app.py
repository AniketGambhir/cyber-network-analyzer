from flask import Flask, render_template, request
from collections import deque
import os

app = Flask(__name__)


# -------------------------------------------------
# BUILD GRAPH
# -------------------------------------------------
def build_graph(devices, connections):
    graph = {device: [] for device in devices}

    for connection in connections:
        device1 = connection["device1"]
        device2 = connection["device2"]

        if device1 in graph and device2 in graph:
            graph[device1].append(device2)
            graph[device2].append(device1)

    return graph


# -------------------------------------------------
# CHECK NETWORK CONNECTIVITY USING BFS
# -------------------------------------------------
def bfs_reachable(graph, start):
    if start not in graph:
        return set()

    visited = set()
    queue = deque([start])

    while queue:
        current = queue.popleft()

        if current in visited:
            continue

        visited.add(current)

        for neighbor in graph[current]:
            if neighbor not in visited:
                queue.append(neighbor)

    return visited


# -------------------------------------------------
# FIND SHORTEST PATH USING BFS
# -------------------------------------------------
def shortest_path(graph, start, destination):
    if start not in graph or destination not in graph:
        return []

    queue = deque([[start]])
    visited = set()

    while queue:
        path = queue.popleft()
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


# -------------------------------------------------
# ANALYZE NETWORK
# -------------------------------------------------
def analyze_network(devices, connections, start, destination):

    graph = build_graph(devices, connections)

    # ---------------------------------------------
    # Connectivity
    # ---------------------------------------------
    reachable = bfs_reachable(graph, devices[0]) if devices else set()

    is_connected = len(reachable) == len(devices)

    # ---------------------------------------------
    # Degree of each device
    # ---------------------------------------------
    degrees = {}

    for device in devices:
        degrees[device] = len(graph.get(device, []))

    # ---------------------------------------------
    # Critical / highly connected devices
    # ---------------------------------------------
    critical_devices = []

    if degrees:
        maximum_degree = max(degrees.values())

        if maximum_degree > 0:
            for device, degree in degrees.items():
                if degree == maximum_degree:
                    critical_devices.append(device)

    # ---------------------------------------------
    # Shortest Path
    # ---------------------------------------------
    path = shortest_path(graph, start, destination)

    # ---------------------------------------------
    # Security Analysis
    # ---------------------------------------------
    unauthorized_connections = []

    for connection in connections:

        if connection["authorized"].lower() == "no":
            unauthorized_connections.append(
                f"{connection['device1']} ↔ {connection['device2']}"
            )

    if unauthorized_connections:
        security_status = "WARNING"
    else:
        security_status = "SAFE"

    # ---------------------------------------------
    # Return all results
    # ---------------------------------------------
    return {
        "total_devices": len(devices),
        "total_connections": len(connections),
        "connected": is_connected,
        "degrees": degrees,
        "critical_devices": critical_devices,
        "shortest_path": path,
        "security_status": security_status,
        "unauthorized_connections": unauthorized_connections,
        "graph": graph
    }


# -------------------------------------------------
# HOME PAGE
# -------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    error = None

    devices_text = ""
    connections_text = ""
    start_device = ""
    destination_device = ""

    if request.method == "POST":

        devices_text = request.form.get("devices", "")
        connections_text = request.form.get("connections", "")
        start_device = request.form.get("start", "").strip()
        destination_device = request.form.get("destination", "").strip()

        # -----------------------------------------
        # READ DEVICES
        # -----------------------------------------
        devices = []

        for line in devices_text.splitlines():

            device = line.strip()

            if device and device not in devices:
                devices.append(device)

        # -----------------------------------------
        # READ CONNECTIONS
        # Format:
        # PC1,Router,yes
        # -----------------------------------------
        connections = []

        for line in connections_text.splitlines():

            line = line.strip()

            if not line:
                continue

            parts = [part.strip() for part in line.split(",")]

            if len(parts) != 3:
                error = (
                    "Invalid connection format. "
                    "Use: Device1,Device2,yes/no"
                )
                break

            device1 = parts[0]
            device2 = parts[1]
            authorized = parts[2].lower()

            if device1 not in devices:
                error = f"Device '{device1}' is not present in the device list."
                break

            if device2 not in devices:
                error = f"Device '{device2}' is not present in the device list."
                break

            if authorized not in ["yes", "no"]:
                error = (
                    f"Invalid security value for {device1} - {device2}. "
                    "Use yes or no."
                )
                break

            connections.append({
                "device1": device1,
                "device2": device2,
                "authorized": authorized
            })

        # -----------------------------------------
        # VALIDATION
        # -----------------------------------------
        if not devices and not error:
            error = "Please enter at least one device."

        if start_device and start_device not in devices and not error:
            error = f"Start device '{start_device}' was not found."

        if destination_device and destination_device not in devices and not error:
            error = f"Destination device '{destination_device}' was not found."

        # -----------------------------------------
        # ANALYZE
        # -----------------------------------------
        if not error:

            result = analyze_network(
                devices,
                connections,
                start_device,
                destination_device
            )

    return render_template(
        "index.html",
        result=result,
        error=error,
        devices_text=devices_text,
        connections_text=connections_text,
        start_device=start_device,
        destination_device=destination_device
    )


# -------------------------------------------------
# RUN APPLICATION
# -------------------------------------------------
if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )