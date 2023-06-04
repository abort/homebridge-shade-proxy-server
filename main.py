from flask import Flask, jsonify, request, Response, abort, json
import asyncio
from bleak import BleakClient
import textwrap
import uuid

app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True

@app.errorhandler(Exception)
def exception_handler(error):
    res = { "error": str(error) }
    app.logger.error(e)
    return Response(status = 500, mimetype = "application/json", response = json.dumps(res))

def error_400_handler(error):
    res = { "error": "Invalid/incomplete JSON received"}
    return Response(status = 401, mimetype = "application/json", response = json.dumps(res))

@app.route("/api/write", methods=['POST'])
def write_api():
    verify_json(request)
    data = request.json
    mac_address = data['address']
    payload = data['payload']

    # expect hexadecimal payload like copied from a Wireshark: adbacd02c0010601
    buffer = bytearray([ int(g, 16) for g in textwrap.wrap(payload, 2) ])

    asyncio.run(write(mac_address, buffer))
    return { "result": "ok" }

async def write(address, payload):
    app.logger.info("Sending payload %s to %s", payload, address)
    client = BleakClient(address, timeout = 15.0)
    try:
        await client.connect()
        # get selected service using uuid
        svc = client.services.get_service(uuid.UUID("00001521-3d1c-019e-ab4a-65fd86e87333"))
        # get defined characteristic from a selected service using characteristic uuid
        characteristic = svc.get_characteristic(uuid.UUID("00001523-3d1c-019e-ab4a-65fd86e87333"))
        await client.write_gatt_char(characteristic, payload, True)
    except Exception as e:
        raise e
    finally:
        await client.disconnect()

def verify_json(request):
    if not request.is_json:
        abort(400)

    data = request.json
    if "address" not in data:
        app.logger.error("bte mac address not in json body")
        abort(400)
    if "payload" not in data:
        app.logger.error("bte payload not in json body")
        abort(400)

app.register_error_handler(400, error_400_handler)