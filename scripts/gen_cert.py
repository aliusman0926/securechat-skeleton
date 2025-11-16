import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import os

if len(sys.argv) != 2 or sys.argv[1] not in ['client', 'server']:
    print("Usage: python scripts/gen_cert.py [client|server]")
    sys.exit(1)

entity = sys.argv[1]

# Load CA private key
with open('certs/ca_key.pem', 'rb') as f:
    ca_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# Load CA certificate
with open('certs/ca_cert.pem', 'rb') as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# Generate entity private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Write entity private key
key_path = f'certs/{entity}_key.pem'
with open(key_path, 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Set subject name
cn = "SecureChat Client" if entity == 'client' else "localhost"  # Use 'localhost' for server to allow hostname match
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lahore"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES"),
    x509.NameAttribute(NameOID.COMMON_NAME, cn),
])

# Build CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
    private_key, hashes.SHA256()
)

# Build the certificate (signed by CA)
cert_builder = x509.CertificateBuilder(
    issuer_name=ca_cert.subject,
    subject_name=csr.subject,
    public_key=csr.public_key(),
    serial_number=x509.random_serial_number(),
    not_valid_before=datetime.datetime.now(datetime.timezone.utc),
    not_valid_after=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365),
).add_extension(
    x509.BasicConstraints(ca=False, path_length=None), critical=True
)

# For server, add SAN for hostname
if entity == 'server':
    cert_builder = cert_builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False
    )

cert = cert_builder.sign(
    private_key=ca_private_key,
    algorithm=hashes.SHA256()
)

# Write entity certificate
cert_path = f'certs/{entity}_cert.pem'
with open(cert_path, 'wb') as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print(f"{entity.capitalize()} certificate generated: {key_path} and {cert_path}")