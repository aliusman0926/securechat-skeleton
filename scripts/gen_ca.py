from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import os

# Ensure certs directory exists in the project root
os.makedirs('certs', exist_ok=True)

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Write private key to file (PEM format, no encryption for simplicity; in production, encrypt it)
with open('certs/ca_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Create subject and issuer (same for self-signed CA)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lahore"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
])

# Build the certificate
cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)  # 10 years
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True
).sign(private_key, hashes.SHA256())

# Write certificate to file (PEM format)
with open('certs/ca_cert.pem', 'wb') as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("Root CA generated: ca_key.pem and ca_cert.pem in certs/")