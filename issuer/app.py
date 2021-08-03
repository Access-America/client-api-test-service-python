import json
import uuid
from datetime import datetime, timezone
from random import randint

import requests
from flask import Flask
from flask import request, redirect
from flask_caching import Cache

cache_config = {
    'DEBUG': True,  # some Flask specific configs
    'CACHE_TYPE': 'SimpleCache',  # Flask-Caching related configs
    'CACHE_DEFAULT_TIMEOUT': 300
}
app = Flask(__name__, static_url_path='', static_folder='static', template_folder='static')

app.config.from_mapping(cache_config)
cache = Cache(app)

issuance_file = 'issuance_request_config_v2.json'
with open(issuance_file) as f:
    issuance_config = json.load(f)

manifest_url = issuance_config['issuance']['manifest']
manifest = requests.get(manifest_url).json()

issuance_config['registration']['clientName'] = 'Python Client API Verifier'

# Use the default issuer if we don't have one configured
if not issuance_config['authority'].startswith('did:ion:'):
    issuance_config['authority'] = manifest['input']['issuer']

if not issuance_config['issuance']['type']:
    issuance_config['issuance']['type'] = manifest['id']

if not issuance_config['issuance']['pin']['length']:
    del issuance_config['issuance']['pin']


@app.route('/')
def root():
    return app.send_static_file('index.html')


@app.route('/logo.png', methods=['GET'])
def logo_redirector():
    return redirect(str(manifest['display']['card']['logo']['uri']))


@app.route('/echo', methods=['GET'])
def echo():
    response = {
        'date': datetime.now(tz=timezone.utc).isoformat(),
        'api': request.url,
        'Host': request.headers.get('host'),
        'x-forwarded-for': request.headers.get('x-forwarded-for'),
        'x-original-host': request.headers.get('x-original-host'),
        'issuerDid': issuance_config['authority'],
        'credentialType': issuance_config['issuance']['type'],
        'displayCard': manifest['display']['card'],
        'buttonColor': '#000080',
        'selfAssertedClaims': issuance_config['issuance'].get('claims')
    }
    return response


@app.route('/issue-request-api', methods=['GET'])
def presentation_request():
    id_ = str(uuid.uuid4())
    payload = issuance_config.copy()
    payload['callback']['url'] = request.url_root.replace('http://', 'https://') + 'issue-request-api-callback'
    payload['callback']['state'] = id_

    pin_length = payload['issuance']['pin']['length']
    pin_code = ''.join(str(randint(0, 9)) for _ in range(pin_length))
    payload['issuance']['pin']['value'] = pin_code

    claims = issuance_config['issuance'].get('claims') or []
    for claim in claims:
        payload['issuance']['claims'][claim] = id_ = request.args.get(claim)
    response = requests.post('https://dev.did.msidentity.com/v1.0/abc/verifiablecredentials/request', json=payload)
    response = response.json()
    response['id'] = id_
    if 'pin' in payload['issuance'] is not None:
        response['pin'] = pin_code

    return response


@app.route('/issue-request-api-callback', methods=['POST'])
def issuance_request_api_callback():
    issuance_response = request.json
    if issuance_response['code'] == 'request_retrieved':
        cache_data = {
            'status': 1,
            'message': 'QR Code is scanned. Complete issuance in Authenticator.'
        }
        cache.set(issuance_response['state'], json.dumps(cache_data))
    return ''


@app.route('/issue-response-status', methods=['GET'])
def issuance_request_status():
    id_ = request.args.get('id')
    data = cache.get(id_)
    if not data:
        return ''

    cache_data = json.loads(data)
    browser_data = {
        'status': cache_data['status'],
        'message': cache_data['message']
    }
    return browser_data


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081)
