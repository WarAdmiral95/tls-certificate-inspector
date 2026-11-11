import os, re, subprocess, tempfile, secrets, base64
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448, padding
from cryptography.x509.oid import ExtensionOID

PEM = re.compile(rb'-----BEGIN CERTIFICATE-----\s*.*?-----END CERTIFICATE-----', re.S)
MAX_BYTES = 512 * 1024

def load_certs(data):
    if len(data) > MAX_BYTES: raise ValueError('Certificate input exceeds 512 KiB')
    blocks = PEM.findall(data)
    if blocks:
        certs = [x509.load_pem_x509_certificate(p) for p in blocks]
        return certs
    try: return [x509.load_der_x509_certificate(data)]
    except ValueError: raise ValueError('No valid PEM or DER X.509 certificates found')

def order_chain(certs):
    """Order a bundle leaf -> ... -> root by following issuer/subject links.
    Returns (ordered_certs, notes). Certificates that cannot be linked are appended at the end."""
    notes = []
    uniq = []; seen = set()
    for c in certs:
        fp = c.fingerprint(hashes.SHA256())
        if fp in seen: notes.append('Duplicate certificate ignored'); continue
        seen.add(fp); uniq.append(c)
    if len(uniq) < 2: return uniq, notes
    def self_signed(c): return c.subject == c.issuer
    issuers = {c.issuer for c in uniq if not self_signed(c)}
    leaves = [c for c in uniq if c.subject not in issuers]
    start = leaves[0] if leaves else uniq[0]
    if len(leaves) > 1: notes.append('Bundle contains more than one possible leaf; the first was used to build the chain')
    ordered = [start]; remaining = [c for c in uniq if c is not start]
    while remaining and not self_signed(ordered[-1]):
        nxt = next((c for c in remaining if c.subject == ordered[-1].issuer and signature_ok(ordered[-1], c)), None)
        if nxt is None: break
        ordered.append(nxt); remaining.remove(nxt)
    if remaining:
        notes.append(f'{len(remaining)} certificate(s) could not be linked into the chain and were placed at the end')
        ordered.extend(remaining)
    if [c.fingerprint(hashes.SHA256()) for c in ordered] != [c.fingerprint(hashes.SHA256()) for c in uniq]:
        notes.append('Certificates were reordered automatically into leaf → intermediate → root order')
    return ordered, notes

def ext(cert, klass):
    try: return cert.extensions.get_extension_for_class(klass).value
    except x509.ExtensionNotFound: return None

EXT_NAMES = {
    '2.5.29.14':'Subject Key Identifier','2.5.29.15':'Key Usage','2.5.29.17':'Subject Alternative Name',
    '2.5.29.19':'Basic Constraints','2.5.29.31':'CRL Distribution Points','2.5.29.32':'Certificate Policies',
    '2.5.29.35':'Authority Key Identifier','2.5.29.37':'Extended Key Usage','1.3.6.1.5.5.7.1.1':'Authority Information Access',
    '1.3.6.1.4.1.11129.2.4.2':'Signed Certificate Timestamps (CT)','2.5.29.30':'Name Constraints','2.5.29.36':'Policy Constraints',
    '1.3.6.1.4.1.11129.2.4.3':'CT Precertificate Poison','2.5.29.18':'Issuer Alternative Name','2.5.29.54':'Inhibit Any Policy',
    '1.3.6.1.5.5.7.1.24':'TLS Feature (OCSP Must-Staple)',
}
EKU_NAMES = {
    '1.3.6.1.5.5.7.3.1':'TLS Web Server Authentication','1.3.6.1.5.5.7.3.2':'TLS Web Client Authentication',
    '1.3.6.1.5.5.7.3.3':'Code Signing','1.3.6.1.5.5.7.3.4':'Email Protection','1.3.6.1.5.5.7.3.8':'Time Stamping',
    '1.3.6.1.5.5.7.3.9':'OCSP Signing','2.5.29.37.0':'Any Extended Key Usage',
}
KU_LABELS = [('digital_signature','Digital Signature'),('content_commitment','Content Commitment'),('key_encipherment','Key Encipherment'),
             ('data_encipherment','Data Encipherment'),('key_agreement','Key Agreement'),('key_cert_sign','Certificate Sign'),('crl_sign','CRL Sign')]

EXT_NAMES.update({
    '2.16.840.1.113730.1.1':'Netscape Certificate Type','2.16.840.1.113730.1.4':'Netscape CA Revocation URL',
    '2.16.840.1.113730.1.8':'Netscape CA Policy URL','2.16.840.1.113730.1.12':'Netscape SSL Server Name',
    '2.16.840.1.113730.1.13':'Netscape Comment',
})
_STR_TAGS = {0x0C:'utf-8', 0x13:'ascii', 0x14:'latin-1', 0x16:'ascii', 0x1A:'ascii', 0x1E:'utf-16-be', 0x1C:'utf-32-be', 0x12:'ascii', 0x19:'ascii'}
_NS_CERT_TYPE = ['SSL Client','SSL Server','S/MIME','Object Signing','Reserved','SSL CA','S/MIME CA','Object Signing CA']

def _der(data, pos=0):
    """Parse one DER TLV. Returns (tag, content, next_pos). Raises ValueError if malformed."""
    if pos + 2 > len(data): raise ValueError
    tag = data[pos]; ln = data[pos + 1]; pos += 2
    if tag & 0x1F == 0x1F: raise ValueError  # multi-byte tags are not handled
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or pos + n > len(data): raise ValueError
        ln = int.from_bytes(data[pos:pos + n], 'big'); pos += n
    if pos + ln > len(data): raise ValueError
    return tag, data[pos:pos + ln], pos + ln

def _oid_text(content):
    try:
        oid = x509.ObjectIdentifier(_oid_dotted(content))
        return oid._name if oid._name and oid._name != 'Unknown OID' else oid.dotted_string
    except Exception: return _hex(content)

def _oid_dotted(b):
    parts = []; v = 0
    for x in b:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80: parts.append(v); v = 0
    first = parts[0]
    head = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return '.'.join(map(str, head + parts[1:]))

_STR_NAMES = {0x0C:'UTF8String', 0x13:'PrintableString', 0x14:'T61String', 0x16:'IA5String', 0x1A:'VisibleString', 0x1E:'BMPString', 0x1C:'UniversalString', 0x12:'NumericString', 0x19:'GraphicString'}

def _der_lines(data, depth=0, limit=60):
    lines = []; pos = 0; pad = '  ' * depth
    while pos < len(data) and len(lines) < limit:
        tag, c, pos = _der(data, pos)
        cls = tag >> 6; num = tag & 0x1F; constructed = bool(tag & 0x20)
        if cls == 0 and num in _STR_TAGS:
            lines.append(f'{pad}{_STR_NAMES[num]}: {c.decode(_STR_TAGS[num])}')
        elif cls == 0 and num == 0x01: lines.append(f"{pad}BOOLEAN: {'TRUE' if c and c[0] else 'FALSE'}")
        elif cls == 0 and num == 0x02:
            n = int.from_bytes(c, 'big', signed=True)
            lines.append(f'{pad}INTEGER: ' + (str(n) if len(c) <= 8 else _hex(c)))
        elif cls == 0 and num == 0x05: lines.append(pad + 'NULL')
        elif cls == 0 and num == 0x06: lines.append(f'{pad}OBJECT: {_oid_text(c)}')
        elif cls == 0 and num in (0x17, 0x18): lines.append(f"{pad}{'UTCTime' if num == 0x17 else 'GeneralizedTime'}: {c.decode('ascii')}")
        elif cls == 0 and num == 0x03:
            lines.append(pad + 'BIT STRING: ' + (''.join(f'{b:08b}' for b in c[1:]) or '(empty)')[: max(0, len(c[1:]) * 8 - c[0])])
        elif cls == 0 and num == 0x04:
            try:
                inner = _der_lines(c, depth + 1, limit)
                if not inner: raise ValueError
                lines.append(pad + 'OCTET STRING (contains):'); lines.extend(inner)
            except Exception:
                lines.append(pad + 'OCTET STRING: ' + (c.decode('ascii') if c and all(32 <= b < 127 for b in c) else _hex(c)))
        elif constructed:
            label = 'SEQUENCE' if cls == 0 and num == 0x10 else 'SET' if cls == 0 and num == 0x11 else f'[{num}]'
            lines.append(f'{pad}{label}:')
            lines.extend(_der_lines(c, depth + 1, limit))
        else:
            lines.append(f'{pad}' + (f'[{num}] ' if cls else '') + (c.decode('ascii') if c and all(32 <= b < 127 for b in c) else _hex(c)))
    return lines

def fmt_unknown(oid, raw):
    """Unrecognised extensions are shown like OpenSSL does: raw bytes, non-printable ones as dots."""
    dotted = oid.dotted_string
    try:
        if dotted == '2.16.840.1.113730.1.1':  # Netscape cert type: BIT STRING
            tag, c, _ = _der(raw)
            bits = ''.join(f'{b:08b}' for b in c[1:])
            names = [n for i, n in enumerate(_NS_CERT_TYPE) if i < len(bits) and bits[i] == '1']
            if names: return '\n'.join(names)
        if dotted in ('2.16.840.1.113730.1.13', '2.16.840.1.113730.1.12', '2.16.840.1.113730.1.4', '2.16.840.1.113730.1.8'):  # Netscape text fields
            tag, c, _ = _der(raw)
            if tag in _STR_TAGS: return c.decode(_STR_TAGS[tag])
    except Exception:
        pass
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)

def ext_name(oid):
    return EXT_NAMES.get(oid.dotted_string) or (oid._name if oid._name and oid._name != 'Unknown OID' else oid.dotted_string)

def _hex(b): return b.hex(':').upper()

def _gn(g):
    if isinstance(g, x509.DNSName): return f'DNS: {g.value}'
    if isinstance(g, x509.IPAddress): return f'IP: {g.value}'
    if isinstance(g, x509.RFC822Name): return f'Email: {g.value}'
    if isinstance(g, x509.UniformResourceIdentifier): return f'URI: {g.value}'
    if isinstance(g, x509.DirectoryName): return f'Directory: {g.value.rfc4514_string()}'
    return str(g.value)

def fmt_ext(v):
    """Render an extension value as plain, readable text."""
    try:
        if isinstance(v, x509.BasicConstraints):
            s = 'Certificate Authority: ' + ('Yes' if v.ca else 'No')
            return s + (f'\nMax path length: {v.path_length}' if v.path_length is not None else '')
        if isinstance(v, x509.KeyUsage):
            return '\n'.join(label for attr, label in KU_LABELS if getattr(v, attr)) + \
                   ('\nEncipher Only' if v.key_agreement and v.encipher_only else '') + ('\nDecipher Only' if v.key_agreement and v.decipher_only else '')
        if isinstance(v, x509.ExtendedKeyUsage):
            return '\n'.join(EKU_NAMES.get(o.dotted_string) or o._name or o.dotted_string for o in v)
        if isinstance(v, (x509.SubjectAlternativeName, x509.IssuerAlternativeName)):
            return '\n'.join(_gn(g) for g in v)
        if isinstance(v, x509.SubjectKeyIdentifier): return _hex(v.digest)
        if isinstance(v, x509.AuthorityKeyIdentifier):
            out = []
            if v.key_identifier: out.append('Key ID: ' + _hex(v.key_identifier))
            if v.authority_cert_issuer: out.append('Issuer: ' + ', '.join(_gn(g) for g in v.authority_cert_issuer))
            if v.authority_cert_serial_number is not None: out.append('Serial: ' + hex(v.authority_cert_serial_number))
            return '\n'.join(out)
        if isinstance(v, x509.AuthorityInformationAccess):
            return '\n'.join(f"{'OCSP' if d.access_method == x509.oid.AuthorityInformationAccessOID.OCSP else 'CA Issuers' if d.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS else d.access_method.dotted_string}: {getattr(d.access_location, 'value', d.access_location)}" for d in v)
        if isinstance(v, x509.CRLDistributionPoints):
            out = []
            for p in v:
                out += [_gn(n) for n in (p.full_name or [])]
                if p.relative_name: out.append(p.relative_name.rfc4514_string())
            return '\n'.join(out)
        if isinstance(v, x509.CertificatePolicies):
            out = []
            for p in v:
                out.append('Policy: ' + (p.policy_identifier._name if p.policy_identifier._name and p.policy_identifier._name != 'Unknown OID' else p.policy_identifier.dotted_string))
                for q in p.policy_qualifiers or []:
                    out.append('  ' + (q if isinstance(q, str) else 'User notice'))
            return '\n'.join(out)
        if isinstance(v, (x509.PrecertificateSignedCertificateTimestamps, x509.SignedCertificateTimestamps)):
            out = []
            for i, s in enumerate(v, 1):
                out.append(f'SCT {i}: logged {s.timestamp.strftime("%Y-%m-%d %H:%M UTC")} · log ID {_hex(s.log_id)[:23]}…')
            return '\n'.join(out)
        if isinstance(v, x509.PrecertPoison): return 'Precertificate (not for use on servers)'
        if isinstance(v, x509.TLSFeature): return '\n'.join(str(f.name).replace('_', ' ') for f in v)
        if isinstance(v, x509.UnrecognizedExtension): return fmt_unknown(v.oid, v.value)
    except Exception:
        pass
    return 'Present (details not decoded)'

def info(c):
    now = datetime.now(timezone.utc)
    bc = ext(c,x509.BasicConstraints)
    san = ext(c,x509.SubjectAlternativeName)
    ku = ext(c,x509.KeyUsage)
    eku = ext(c,x509.ExtendedKeyUsage)
    return {'subject':c.subject.rfc4514_string(),'issuer':c.issuer.rfc4514_string(),
      'not_before':c.not_valid_before_utc.isoformat(),'not_after':c.not_valid_after_utc.isoformat(),
      'days_remaining':(c.not_valid_after_utc-now).days,'currently_valid':c.not_valid_before_utc<=now<=c.not_valid_after_utc,
      'sha256':c.fingerprint(hashes.SHA256()).hex(':').upper(),'serial':hex(c.serial_number),
      'signature_algorithm':c.signature_algorithm_oid._name or c.signature_algorithm_oid.dotted_string,
      'public_key_type':type(c.public_key()).__name__,'public_key_bits':getattr(c.public_key(),'key_size',None),
      'is_ca':bool(bc.ca) if bc else False,'path_length':bc.path_length if bc else None,
      'dns_names':san.get_values_for_type(x509.DNSName) if san else [],
      'ip_addresses':[str(x) for x in san.get_values_for_type(x509.IPAddress)] if san else [],
      'key_usage':{n:getattr(ku,n) for n in ('digital_signature','content_commitment','key_encipherment','data_encipherment','key_agreement','key_cert_sign','crl_sign') } if ku else None,
      'extended_key_usage':[oid.dotted_string for oid in eku] if eku else [],
      'extensions':[{'oid':e.oid.dotted_string,'name':ext_name(e.oid),'critical':e.critical,'value':fmt_ext(e.value)[:4000]} for e in c.extensions],
      'pem':c.public_bytes(serialization.Encoding.PEM).decode()}

def signature_ok(child,parent):
    k=parent.public_key()
    try:
        if isinstance(k,rsa.RSAPublicKey):
            params=child.signature_algorithm_parameters
            k.verify(child.signature,child.tbs_certificate_bytes,params if params is not None else padding.PKCS1v15(),child.signature_hash_algorithm)
        elif isinstance(k,ec.EllipticCurvePublicKey): k.verify(child.signature,child.tbs_certificate_bytes,ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(k,dsa.DSAPublicKey): k.verify(child.signature,child.tbs_certificate_bytes,child.signature_hash_algorithm)
        elif isinstance(k,(ed25519.Ed25519PublicKey,ed448.Ed448PublicKey)): k.verify(child.signature,child.tbs_certificate_bytes)
        else: return False
        return True
    except Exception: return False

def validate(certs, trust_roots=None):
    roots=trust_roots or []
    errors=[]; warnings=[]; now=datetime.now(timezone.utc)
    for i,c in enumerate(certs):
        if not c.not_valid_before_utc<=now<=c.not_valid_after_utc: errors.append(f'Certificate {i+1} is expired or not yet valid')
    # Check chain as supplied, in order, with root optionally omitted.
    for i in range(len(certs)-1):
        child,parent=certs[i:i+2]
        if child.issuer!=parent.subject: errors.append(f'Issuer mismatch between certificates {i+1} and {i+2}')
        if not signature_ok(child,parent): errors.append(f'Invalid signature between certificates {i+1} and {i+2}')
        bc=ext(parent,x509.BasicConstraints)
        if not bc or not bc.ca: errors.append(f'Certificate {i+2} is not a CA')
        ku=ext(parent,x509.KeyUsage)
        if ku and not ku.key_cert_sign: errors.append(f'Certificate {i+2} cannot sign certificates')
        if bc and bc.path_length is not None:
            subordinate=sum(bool(ext(c,x509.BasicConstraints) and ext(c,x509.BasicConstraints).ca and c.subject!=c.issuer) for c in certs[:i+1])
            if subordinate>bc.path_length: errors.append(f'Path length exceeded at certificate {i+2}')
    anchor=None
    for root in roots:
        if certs[-1].fingerprint(hashes.SHA256())==root.fingerprint(hashes.SHA256()): anchor=root; break
        if certs[-1].issuer==root.subject and signature_ok(certs[-1],root): anchor=root; break
    if anchor:
        if not ext(anchor,x509.BasicConstraints) or not ext(anchor,x509.BasicConstraints).ca: errors.append('Trust anchor is not a CA certificate')
        if not anchor.not_valid_before_utc<=now<=anchor.not_valid_after_utc: errors.append('Trust anchor is expired or not yet valid')
    else:
        last=certs[-1]
        if last.subject==last.issuer and signature_ok(last,last) and ext(last,x509.BasicConstraints) and ext(last,x509.BasicConstraints).ca:
            warnings.append('Self-signed root found, but not independently trusted unless explicitly supplied as a trust anchor')
        else: warnings.append('Chain does not terminate at a supplied trust anchor')
    if not errors and not anchor: warnings.append('Cryptographic links check out, but trust is not established')
    return {'valid':not errors and anchor is not None,'chain_signatures_valid':not errors,
            'trusted':anchor is not None,'errors':errors,'warnings':warnings,
            'note':'Structural chain checks, not full RFC 5280 path validation or public PKI/hostname verification.'}

def run(args,timeout=15,env=None):
    p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,env=env)
    if p.returncode: raise ValueError('JKS conversion failed. Check certificates, private key, password, and chain order.')

def password_check(password):
    if not 6<=len(password)<=256: raise ValueError('JKS password must be 6–256 characters')
    if '\x00' in password: raise ValueError('Password cannot contain NUL')

def truststore(certs,password):
    password_check(password)
    if len(certs)>30: raise ValueError('Maximum 30 certificates')
    if any(not (ext(c,x509.BasicConstraints) and ext(c,x509.BasicConstraints).ca) for c in certs):
        raise ValueError('Truststore input must contain CA certificates only')
    with tempfile.TemporaryDirectory() as td:
        store=Path(td)/'truststore.jks'
        env={**os.environ,'JKS_USER_PASS':password}
        for i,c in enumerate(certs):
            certfile=Path(td)/f'ca{i}.pem'; certfile.write_bytes(c.public_bytes(serialization.Encoding.PEM))
            run(['keytool','-importcert','-noprompt','-storetype','JKS','-keystore',str(store),'-alias',f'ca-{i+1}', '-file',str(certfile),'-storepass:env','JKS_USER_PASS'],env=env)
        return store.read_bytes()

def keystore(certs,key_data,password,key_password=None,alias='server'):
    password_check(password)
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',alias): raise ValueError('Invalid alias')
    if len(key_data)>MAX_BYTES: raise ValueError('Private key too large')
    try: key=serialization.load_pem_private_key(key_data,password=key_password.encode() if key_password else None)
    except (ValueError,TypeError): raise ValueError('Could not read private key; check PEM and key password')
    leaf=certs[0]
    if key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)!=leaf.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo):
        raise ValueError('Private key does not match the first (leaf) certificate')
    if ext(leaf,x509.BasicConstraints) and ext(leaf,x509.BasicConstraints).ca: raise ValueError('First certificate must be a leaf, not a CA')
    # Validate adjacency, even when no root was supplied.
    for i in range(len(certs)-1):
        if certs[i].issuer!=certs[i+1].subject or not signature_ok(certs[i],certs[i+1]):
            raise ValueError(f'Invalid chain order or signature at certificates {i+1} and {i+2}')
    from cryptography.hazmat.primitives.serialization import pkcs12
    with tempfile.TemporaryDirectory() as td:
        p12=Path(td)/'key.p12'; dest=Path(td)/'keystore.jks'
        # Temporary random internal password, never user secret in command arguments.
        internal=secrets.token_urlsafe(30)
        p12.write_bytes(pkcs12.serialize_key_and_certificates(alias.encode(),key,leaf,certs[1:],serialization.BestAvailableEncryption(internal.encode())))
        os.chmod(p12,0o600)
        # keytool importkeystore reads destination password from stdin, source password supplied via environment
        env={**os.environ,'INTERNAL_P12_PASS':internal}
        # keytool supports -srcstorepass:env and -deststorepass:env (avoid secrets in process argv)
        env['JKS_USER_PASS']=password
        run(['keytool','-importkeystore','-noprompt','-srckeystore',str(p12),'-srcstoretype','PKCS12','-srcstorepass:env','INTERNAL_P12_PASS','-destkeystore',str(dest),'-deststoretype','JKS','-deststorepass:env','JKS_USER_PASS'],env=env)
        return dest.read_bytes()
