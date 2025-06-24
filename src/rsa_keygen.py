from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_key_pair(private_key_path: str, public_key_path: str) -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    Path(private_key_path).write_bytes(private_pem)
    Path(public_key_path).write_bytes(public_pem)
