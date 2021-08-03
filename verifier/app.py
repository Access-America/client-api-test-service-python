import base64
import json
import logging
import uuid
from datetime import datetime, timezone

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

log = logging.getLogger()
log.setLevel(logging.INFO)

presentation_file = 'presentation_request_config_v2.json'
with open(presentation_file) as f:
    presentation_config = json.load(f)

manifest_url = presentation_config['presentation']['requestedCredentials'][0]['manifest']
manifest = requests.get(manifest_url).json()

presentation_config['registration']['clientName'] = 'Python Client API Verifier'
presentation_config['presentation']['requestedCredentials'][0]['trustedIssuers'][0] = manifest['input']['issuer']

if not presentation_config['authority'].startswith('did:ion:'):
    presentation_config['authority'] = manifest['input']['issuer']

if not presentation_config['presentation']['requestedCredentials'][0]['type']:
    presentation_config['presentation']['requestedCredentials'][0]['type'] = manifest['id']


@app.route('/')
def root():
    return app.send_static_file('index.html')


@app.route('/logo.png', methods=['GET'])
def logo_redirector():
    return redirect(str(manifest['display']['card']['logo']['uri']))


@app.route('/echo', methods=['GET'])
def echo():
    credentials = presentation_config['presentation']['requestedCredentials'][0]
    result = {
        'date': datetime.now(tz=timezone.utc).isoformat(),
        'api': request.url,
        'Host': request.headers.get('host'),
        'x-forwarded-for': request.headers.get('x-forwarded-for'),
        'x-original-host': request.headers.get('x-original-host'),
        'issuerDid': credentials['trustedIssuers'][0],
        'credentialType': credentials['type'],
        'client_purpose': credentials['purpose'],
        'displayCard': manifest['display']['card'],
        'buttonColor': '#000080'
    }
    return result


@app.route('/presentation-request', methods=['GET'])
def presentation_request():
    id_ = str(uuid.uuid4())
    payload = presentation_config.copy()
    payload['callback']['url'] = request.url_root.replace('http://', 'https://') + 'presentation-request-api-callback'
    payload['callback']['state'] = id_
    response = requests.post('https://dev.did.msidentity.com/v1.0/abc/verifiablecredentials/request', json=payload)
    response = response.json()
    response['id'] = id_
    return response


@app.route('/presentation-request-api-callback', methods=['GET'])
def presentation_request_api_callback_get():
    print('test')
    return ''


@app.route('/presentation-request-api-callback', methods=['POST'])
def presentation_request_api_callback():
    presentation_response = request.json
    print(presentation_response)
    if presentation_response['code'] == 'request_retrieved':
        cache_data = {
            'status': 1,
            'message': 'QR Code is scanned. Waiting for validation...'
        }
        cache.set(presentation_response['state'], json.dumps(cache_data))
        return ''
    if presentation_response['code'] == 'presentation_verified':
        cache_data = {
            'status': 2,
            'message': 'VC Presented',
            'presentationResponse': presentation_response
        }
        cache.set(presentation_response['state'], json.dumps(cache_data))
        return ''


@app.route('/presentation-response-status', methods=['GET'])
def presentation_request_status():
    id_ = request.args.get('id')
    data = cache.get(id_)
    if not data:
        return ''

    cache_data = json.loads(data)
    browser_data = {
        'status': cache_data['status'],
        'message': cache_data['message']
    }

    if cache_data['status'] == 2:
        browser_data['claims'] = cache_data['presentationResponse']['issuers'][0]['claims']

    return browser_data


def decode_jwt_token(token):
    return json.loads(base64.b64decode(token.split('.')[1] + '==').decode('utf-8'))


@app.route('/presentation-response-b2c', methods=['POST'])
def presentation_response_b2_c():
    presentation_response = request.json
    id_ = presentation_response['id']
    data = cache.get(id_)
    if not data:
        return {
            'version': '1.0.0',
            'status': 400,
            'userMessage': 'Verifiable Credentials not presented'
        }

    cache_data = json.loads(data)
    if cache_data['status'] != 2:
        return {
            'version': '1.0.0',
            'status': 400,
            'userMessage': 'Verifiable Credentials not presented'
        }

    jwt_siop = decode_jwt_token(cache_data['presentationResponse']['receipt']['id_token'])
    jwt_vp = None

    presentations = jwt_siop['attestations']['presentations']
    for p in presentations:
        jwt_vp = decode_jwt_token(presentations[p])

    claims = cache_data['presentationResponse']['issuers'][0]['claims']
    tid = claims.get('tid')
    oid = claims.get('sub')
    username = claims.get('username')

    jwt_vc = decode_jwt_token(jwt_vp['vp']['verifiableCredential'][0])
    response = {
        'id': id_,
        'credentialsVerified': True,
        'credentialType': presentation_config['presentation']['requestedCredentials'][0]['type'],
        'displayName': claims['firstName'] + ' ' + claims['lastName'],
        'givenName': claims['firstName'],
        'surName': claims['lastName'],
        'iss': jwt_vc['iss'],  # who issued this VC?
        'sub': jwt_vc['sub'],  # who are you?
        'key': jwt_vc['sub'].replace('did:ion:', 'did.ion.').split(':')[0].replace('did.ion.', 'did:ion:'),
        'oid': oid,
        'tid': tid,
        'username': username
    }
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8082)
