
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
import argparse

def verifica_assinatura(crt_atual :x509, crt_novo: x509) -> bool:
    pub_key_atual = crt_atual.public_key()
    assinatura = crt_novo.signature
    tbs_infos = crt_novo.tbs_certificate_bytes
    alg_hash = crt_novo.signature_hash_algorithm
    # print(len(tbs_infos))
    # print(tbs_infos.hex())
    print(assinatura.hex())

    try:
        if isinstance(pub_key_atual, ec.EllipticCurvePublicKey):
            pub_key_atual.verify(assinatura, tbs_infos, ec.ECDSA(alg_hash))
        elif isinstance(pub_key_atual, rsa.RSAPublicKey):
            padd = padding.PKCS1v15()
            pub_key_atual.verify(assinatura, tbs_infos, padd, alg_hash)
        return True
    except:
        return False

def cert_info(crt: x509) -> str:
    print("Subject: CN=",crt.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
    print("Issuer: CN=",crt.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
    print("Signature Algorithm: ",crt.signature_algorithm_oid._name)

parser = argparse.ArgumentParser(description='Validar assinatura de certificado.')
parser.add_argument('crt_atual_pem', type=str,
                    help='Certificado atual (PEM)')
parser.add_argument('crt_novo_pem', type=str,
                    help='Certificado novo (PEM)')
parser.add_argument('-d', '--debug', action="store_true",
                    help='Imprimir informações dos certificados')

args = parser.parse_args()
cert_novo_file = args.crt_novo_pem
cert_atual_file = args.crt_atual_pem

cert_novo_pem = open(cert_novo_file, "r").read()
cert_atual_pem = open(cert_atual_file, "r").read()

cert_novo = x509.load_pem_x509_certificate(cert_novo_pem.encode('utf-8'))
cert_atual = x509.load_pem_x509_certificate(cert_atual_pem.encode('utf-8'))

if(args.debug):
    print("------------------------------")
    print("Informações do ", cert_atual_file)
    print("------------------------------")
    cert_info(cert_atual)

    print("\n-------------------------------")
    print("Informações do ", cert_novo_file)
    print("------------------------------")
    cert_info(cert_novo)

result = verifica_assinatura(cert_atual, cert_novo)
print("\nAssinatura válida\n" if result else "\nAssinatura inválida\n")
