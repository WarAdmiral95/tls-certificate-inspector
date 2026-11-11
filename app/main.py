import asyncio, ipaddress, re, socket, ssl, subprocess
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

app = FastAPI(title='TLS Certificate Inspector', docs_url=None, redoc_url=None)
HOST_RE = re.compile(r'^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$')
PEM_RE = re.compile(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)

def name(cert_name):
    return cert_name.rfc4514_string()

def inspect(host):
    if not HOST_RE.fullmatch(host):
        raise ValueError('Enter a valid public DNS hostname (no URL or port).')
    answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    addresses = sorted({item[4][0] for item in answers})
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError('Only publicly routable targets are permitted.')
    # Pin connection to the resolved IP to avoid a second DNS lookup / DNS rebinding.
    ip = addresses[0]
    target = f'[{ip}]:443' if ':' in ip else f'{ip}:443'
    cmd = ['openssl','s_client','-connect',target,'-servername',host,'-showcerts','-brief']
    proc = subprocess.run(cmd, input=b'', capture_output=True, timeout=8)
    output = proc.stdout + b'\n' + proc.stderr
    pems = PEM_RE.findall(output)
    if not pems:
        # -brief is not supported consistently with -showcerts on some OpenSSL builds
        cmd.remove('-brief')
        proc = subprocess.run(cmd, input=b'', capture_output=True, timeout=8)
        output = proc.stdout + b'\n' + proc.stderr
        pems = PEM_RE.findall(output)
    if not pems:
        raise ValueError('No TLS certificate received from the server.')
    certs = []
    now = datetime.now(timezone.utc)
    for pem in pems:
        c = x509.load_pem_x509_certificate(pem)
        start = c.not_valid_before_utc
        end = c.not_valid_after_utc
        try:
            sans = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        certs.append({'subject':name(c.subject),'issuer':name(c.issuer),'not_before':start.isoformat(),
                      'not_after':end.isoformat(),'days_remaining':(end-now).days,
                      'sha256':c.fingerprint(hashes.SHA256()).hex(':').upper(),
                      'serial':hex(c.serial_number),'dns_names':sans[:100]})
    # Separate validated handshake: verification checks trust and hostname.
    verified = False
    verification_error = None
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip,443),timeout=5) as raw:
            with context.wrap_socket(raw,server_hostname=host) as tls:
                version = tls.version()
                cipher = tls.cipher()[0]
                verified = True
    except Exception as e:
        verification_error = str(e)[:240]
        version = None
        cipher = None
    return {'hostname':host,'resolved_ip':ip,'verified':verified,'verification_error':verification_error,
            'tls_version':version,'cipher':cipher,'certificates':certs,
            'note':'Chain shows certificates sent by the server; root CA may be omitted.'}

@app.get('/healthz')
def health(): return {'ok':True}

@app.get('/api/inspect')
async def api_inspect(host: str = Query(min_length=1,max_length=253)):
    try:
        return await asyncio.wait_for(asyncio.to_thread(inspect,host.strip().lower()),timeout=18)
    except (ValueError, socket.gaierror, subprocess.TimeoutExpired, TimeoutError, OSError) as e:
        raise HTTPException(status_code=400,detail=str(e)[:300])
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504,detail='TLS inspection timed out')

@app.get('/',response_class=HTMLResponse)
def index():
    with open('/app/index.html',encoding='utf-8') as f: return f.read()

from fastapi import Request
from fastapi.responses import Response
from toolkit import load_certs, info, validate, truststore, keystore, order_chain, ext, signature_ok

@app.post('/api/certificates/inspect')
async def inspect_uploaded(request: Request):
    try:
        body=await request.json()
        certs=load_certs(body['certificates'].encode())
        if len(certs)>30: raise ValueError('Maximum 30 certificates')
        certs,notes=order_chain(certs)
        roots=load_certs(body['trusted_roots'].encode()) if body.get('trusted_roots') else []
        anchor_source='supplied' if roots else None
        if not roots and len(certs)>1:
            # Single-input mode: a self-signed CA at the end of the bundle is treated as the
            # root the user supplied. This is NOT a public-trust check.
            last=certs[-1]; bc=ext(last,x509.BasicConstraints)
            if last.subject==last.issuer and bc and bc.ca and signature_ok(last,last):
                roots=[last]; anchor_source='bundle'
        result=validate(certs,roots)
        result['auto_notes']=notes
        result['anchor_source']=anchor_source
        return {'certificates':[info(c) for c in certs], 'validation':result}
    except (ValueError,KeyError,TypeError) as e: raise HTTPException(400,str(e))

@app.post('/api/jks/truststore')
async def generate_truststore(request: Request):
    try:
        body=await request.json()
        data=truststore(load_certs(body['certificates'].encode()),body['password'])
        return Response(data,media_type='application/octet-stream',headers={'Content-Disposition':'attachment; filename="truststore.jks"','Cache-Control':'no-store'})
    except (ValueError,KeyError,TypeError) as e: raise HTTPException(400,str(e))

@app.post('/api/jks/keystore')
async def generate_keystore(request: Request):
    try:
        body=await request.json()
        data=keystore(load_certs(body['certificates'].encode()),body['private_key'].encode(),body['password'],body.get('key_password'),body.get('alias','server'))
        return Response(data,media_type='application/octet-stream',headers={'Content-Disposition':'attachment; filename="keystore.jks"','Cache-Control':'no-store'})
    except (ValueError,KeyError,TypeError) as e: raise HTTPException(400,str(e))
