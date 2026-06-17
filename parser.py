from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import datetime

def parse_certificate(pem_cert):
    cert = x509.load_pem_x509_certificate(
        pem_cert.encode(),
        default_backend()
    )
    subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    subject_cn = subject[0].value if subject else "N/A"
    
    issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    issuer_cn = issuer[0].value if issuer else "N/A"

    valid_from  = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    valid_until = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    now = datetime.datetime.now(datetime.timezone.utc)
    days_to_expiry = (valid_until - now).days

    try:                                # exctract sni
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except:
        sans = []

    sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"


    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        pub_key_type = "RSA"
        pub_key_bits = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        pub_key_type = "EC"
        pub_key_bits = pub_key.key_size
    else:
        pub_key_type = "Unkown"
        pub_key_bits = None
    
    self_signed = cert.issuer == cert.subject

    serial = str(cert.serial_number)

    return {
        "subject":            subject_cn,
        "issuer":             issuer_cn,
        "valid_from":         valid_from.strftime("%Y-%m-%d"),
        "valid_until":        valid_until.strftime("%Y-%m-%d"),
        "days_to_expiry":     days_to_expiry,
        "sans":               list(sans),
        "signature_algorithm": sig_alg,
        "public_key_type":    pub_key_type,
        "public_key_bits":    pub_key_bits,
        "self_signed":        self_signed,
        "serial_number":      serial,
    }

if __name__ == "__main__":
    from probe import get_pem_certificate
    pem = get_pem_certificate("github.com")
    import json
    print(json.dumps(parse_certificate(pem), indent=2))