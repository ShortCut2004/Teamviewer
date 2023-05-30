from crypto.PublicKey.RSA import RsaKey

from crypto.Signature.pkcs1_15 import PKCS115_SigScheme


def new(rsa_key: RsaKey) -> PKCS115_SigScheme: ...