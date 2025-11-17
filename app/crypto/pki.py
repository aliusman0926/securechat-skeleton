"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import datetime
import os

# Path to trusted CA certificate
CA_CERT_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'certs', 'ca_cert.pem')

def load_ca_cert() -> x509.Certificate:
    """Load the trusted root CA certificate."""
    with open(CA_CERT_PATH, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())

def verify_certificate_chain(peer_cert_pem: bytes, is_server: bool = False) -> bool:
    """
    Validate a peer certificate:
    - Must be signed by the root CA
    - Must be currently valid (not before / not after)
    - For server: must contain SAN with 'localhost'
    - For client: CN must be 'SecureChat Client'
    """
    try:
        # Load peer certificate
        peer_cert = x509.load_pem_x509_certificate(peer_cert_pem)

        # Load CA certificate
        ca_cert = load_ca_cert()
        ca_public_key = ca_cert.public_key()

        # 1. Verify signature
        ca_public_key.verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            peer_cert.signature_algorithm_parameters,
            peer_cert.signature_hash_algorithm
        )

        # 2. Check validity period
        now = datetime.datetime.now(datetime.timezone.utc)
        if peer_cert.not_valid_before_utc > now or peer_cert.not_valid_after_utc < now:
            return False

        # 3. Check subject name
        cn = peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not cn or len(cn) == 0:
            return False

        if is_server:
            # Server: check SAN for 'localhost'
            san_ext = peer_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            if "localhost" not in dns_names:
                return False
        else:
            # Client: check CN
            if cn[0].value != "SecureChat Client":
                return False

        return True

    except InvalidSignature:
        return False
    except Exception:
        return False
