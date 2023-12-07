#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

using namespace std;

int verifica_assinatura(const char *crt_atual_pem, const char *crt_novo_pem)
{
  int resultado = -1;
  try
  {
    BIO *b = BIO_new(BIO_s_mem());
    BIO_puts(b, crt_atual_pem);
    X509 *cert_atual = PEM_read_bio_X509(b, NULL, NULL, NULL);
    EVP_PKEY *pub_key_atual = X509_get_pubkey(cert_atual);

    BIO *c = BIO_new(BIO_s_mem());
    BIO_puts(c, crt_novo_pem);
    X509 *cert_novo = PEM_read_bio_X509(c, NULL, NULL, NULL);

    resultado = X509_verify(cert_novo, pub_key_atual);

    EVP_PKEY_free(pub_key_atual);
    BIO_free(b);
    BIO_free(c);
    X509_free(cert_novo);
    X509_free(cert_atual);
  }
  catch (int n)
  {
    return n;
  }

  return resultado;
}

void cert_info(const char *cert_pem)
{
  BIO *b = BIO_new(BIO_s_mem());
  BIO_puts(b, cert_pem);
  X509 *cert = PEM_read_bio_X509(b, NULL, 0, NULL);

  BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

  // Subject
  BIO_printf(bio_out, "Subject: ");
  X509_NAME_print(bio_out, X509_get_subject_name(cert), 0);
  BIO_printf(bio_out, "\n");

  // Issuer
  BIO_printf(bio_out, "Issuer: ");
  X509_NAME_print(bio_out, X509_get_issuer_name(cert), 0);
  BIO_printf(bio_out, "\n");

  // Public Key
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
  EVP_PKEY_free(pkey);

  // Signature
  const ASN1_BIT_STRING *assinatura = NULL;
  const X509_ALGOR *alg = NULL;

  X509_get0_signature(&assinatura, &alg, cert);

  X509_signature_print(bio_out, alg, assinatura);

  BIO_printf(bio_out, "\n");

  BIO_free(bio_out);
  BIO_free(b);
  X509_free(cert);
}

//----------------------------------------------------------------------

void sintaxe_invalida(char *argv[])
{
  cout << "Sintaxe: " << argv[0] << " <crt_atual_pem> <crt_novo_pem> [-d]" << endl;
  cout << "Exemplos:" << endl;
  cout << argv[0] << " c2-c1.pem c3-c2.pem" << endl;
  exit(-1);
}

int main(int argc, char **argv)
{
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();

  if (argc < 3)
  {
    sintaxe_invalida(argv);
  }

  string crt_atual_file = argv[1];
  string crt_novo_file = argv[2];

  bool debug;

  if (argc == 4)
  {
    string arg3 = argv[3];
    if (arg3.compare("-d") == 0)
    {
      debug = true;
    }
  }

  ifstream ifs_crt_atual(crt_atual_file);
  ifstream ifs_crt_novo(crt_novo_file);

  ostringstream out_atual;
  ostringstream out_novo;

  out_atual << ifs_crt_atual.rdbuf();
  out_novo << ifs_crt_novo.rdbuf();

  string crt_atual = out_atual.str();
  string crt_novo = out_novo.str();

  // Imprimir informações dos certificados
  if (debug)
  {
    cout << "---------------------------------------------"
         << "\nInformações do Certificado: " << crt_atual_file
         << "\n---------------------------------------------" << endl;
    cert_info(crt_atual.c_str());

    cout << "---------------------------------------------"
         << "\nInformações do Certificado: " << crt_novo_file
         << "\n---------------------------------------------" << endl;
    cert_info(crt_novo.c_str());

    cout << "---------------------------------------------" << endl;
  }

  // Verificando assinatura do novo certificado
  int resultado = verifica_assinatura(crt_atual.c_str(), crt_novo.c_str());

  switch (resultado)
  {
  case 0:
    cout << "Assinatura inválida!" << endl;
    break;
  case 1:
    cout << "Assinatura válida!" << endl;
    break;
  default:
    cout << "Erro ao validar assinatura do certificado "
         << crt_novo_file << "\nutilizando chave pública do certificado "
         << crt_atual_file << "!" << endl;
    break;
  }
  cout << "---------------------------------------------" << endl;
}