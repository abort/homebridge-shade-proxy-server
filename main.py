from flask import Flask, jsonify, request, Response, abort, json
import asyncio
from threading import Lock
from bleak import BleakClient
import textwrap
import uuid
import nest_asyncio
import atexit

nest_asyncio.apply()

app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True

connections = dict()
lock = Lock()
loop = asyncio.new_event_loop()

def remove_hex_prefix(s):
    return s.removeprefix('0x')

async def disconnect_all():
    total = 0
    with lock:
        for address in list(connections.keys()):
            try:
                connection = connections[address]
                if connection.is_connected:
                    await connection.disconnect()
                    total += 1
                    connections.pop(address)
            except Exception as e:
                app.logger.error("Failed to close a connection")
    return total

@app.errorhandler(Exception)
def exception_handler(error):
    res = { "error": str(error) }
    app.logger.error(error)
    return Response(status = 500, mimetype = "application/json", response = json.dumps(res))

def error_400_handler(error):
    res = { "error": "Invalid/incomplete JSON received"}
    return Response(status = 401, mimetype = "application/json", response = json.dumps(res))

@app.route('/api/disconnect', methods=['GET'])
def disconnect_api():
    task = loop.create_task(disconnect_all())
    total = loop.run_until_complete(task)

    return { "total_disconnected": total }

@app.route('/api/count_connections', methods=['GET'])
def count_connections_api():
    return { "total": len(connections) }

@app.route("/api/brightness", methods=['POST'])
def set_brightness_api():
    verify_json(request)
    data = request.json
    mac_address = data['address']
    device_id = remove_hex_prefix(data['deviceId'])
    payload_prefix = remove_hex_prefix(data['payloadPrefix'])
    value = int(data['value'])

    intensity = 0x080000 + int((0x084e20 - 0x080000) / 100 * value)
    write_payload(mac_address, payload_prefix, device_id, intensity.to_bytes(3, "big").hex())
    return { "result": "ok" }

@app.route("/api/toggle", methods=['POST'])
def toggle_api():
    verify_json(request)
    data = request.json
    mac_address = data['address']
    device_id = remove_hex_prefix(data['deviceId'])
    payload_prefix = remove_hex_prefix(data['payloadPrefix'])
    value = data['value']

    toggle_value = 0x0600 | int(value)
    write_payload(mac_address, payload_prefix, device_id, toggle_value.to_bytes(2, "big").hex())
    return { "result": "ok" }

def write_payload(mac_address, payload_prefix, device_id, specific_payload):
    payload = payload_prefix + device_id + specific_payload

    app.logger.info("Writing payload: %s to %s", payload, mac_address)
    # expect hexadecimal payload like copied from a Wireshark: adbacd02c0010601
    buffer = bytearray([ int(g, 16) for g in textwrap.wrap(payload, 2) ])

    task = loop.create_task(write(mac_address, buffer))
    loop.run_until_complete(task)  

def disconnect_callback(client):
    app.logger.info("Disconnected client")
    with lock:
        for address in list(connections.keys()):
            if connections[address] == client:
                connections.pop(address)
                return

async def write(address, payload):
    app.logger.info("Sending payload %s to %s", payload, address)
    with lock:
        try:
            if not address in connections:
                connections[address] = BleakClient(address, disconnect_callback = disconnect_callback, timeout = 15.0)

            client = connections[address]
            # connect or reconnect
            if not client.is_connected:
                await client.connect()

                # get selected service using uuid
                svc = client.services.get_service(uuid.UUID("00001521-3d1c-019e-ab4a-65fd86e87333"))
            # get defined characteristic from a selected service using characteristic uuid
            # characteristic = svc.get_characteristic(uuid.UUID("00001523-3d1c-019e-ab4a-65fd86e87333"))
            await client.write_gatt_char(uuid.UUID("00001523-3d1c-019e-ab4a-65fd86e87333"), payload, True)
        except Exception as e:
            raise e
        finally:
            if not connections[address].is_connected:
                connections.pop(address)

def verify_json(request):
    if not request.is_json:
        abort(400)

    data = request.json
    if "address" not in data:
        app.logger.error("bte mac address not in json body")
        abort(400)
    if "payloadPrefix" not in data:
        app.logger.error("bte payload prefix not in json body")
        abort(400)
    if "deviceId" not in data:
        app.logger.error("bte device id not in json body")
        abort(400)
    if "value" not in data:
        app.logger.error("value to set not in json body")
        abort(400)        

def on_exit():
    task = loop.create_task(disconnect_all())
    total = loop.run_until_complete(task)
    loop.close()

atexit.register(on_exit)

app.register_error_handler(400, error_400_handler)

