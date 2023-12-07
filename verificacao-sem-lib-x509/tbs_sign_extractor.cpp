#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const char oid_ecdsa_with_SHA256[] = "06082a8648ce3d040302";
const char oid_ecdsa_with_SHA384[] = "06082a8648ce3d040303";
const char oid_ecdsa_with_SHA512[] = "06082a8648ce3d040304";
const char oid_sha256_With_RSAEncryption[] = "06092a864886f70d01010b0500";

char der[5000]; 

// Fonte: https://www.rfc-editor.org/rfc/rfc5754#section-3.3
//ecdsa-with-SHA256: 30 0a 06 08 2a 86 48 ce 3d 04 03 02 ->  
//ecdsa-with-SHA384: 30 0a 06 08 2a 86 48 ce 3d 04 03 03 -> 06082a8648ce3d040303
//ecdsa-with-SHA512: 30 0a 06 08 2a 86 48 ce 3d 04 03 04 -> 06082a8648ce3d040304

// Fonte: https://www.rfc-editor.org/rfc/rfc5754#section-3.2
//sha256WithRSAEncryption: 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 -> 06092a864886f70d01010b0500
//sha384WithRSAEncryption: 30 0d 06 09 2a 86 48 86 f7 0d 01 01 Oc 05 00 -> 06092a864886f70d0101Oc0500
//sha512WithRSAEncryption: 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0d 05 00 -> 06092a864886f70d01010d0500

// Converte um determinado número de caracteres hex de uma string em long int
// Útil para strings de hex sem espaço.
long int hextol (const char* str, int num_char){
    char buffer[num_char+1];
    strncpy (buffer, str, num_char);
    buffer[num_char+1] = '\0';
    return strtol(buffer, NULL, 16);
}

// Para verificar qual o oid a ser utilizado pelo argumento informado
const char* message_alg_oid (const char* alg){

    if(strcmp(alg, "sha-256")==0){
        return oid_ecdsa_with_SHA256;
    }else if (strcmp(alg, "sha-384")==0){
       return oid_ecdsa_with_SHA384; 
    }else if (strcmp(alg, "sha-512")==0){
       return oid_ecdsa_with_SHA512; 
    }else if (strcmp(alg, "rsa")==0){
       return oid_sha256_With_RSAEncryption; 
    }
    else {
        return "Valor inválido";
    }
}

int main(int argc, char *argv[]){

    if(argc!=6){
        printf("Usage example: ./tbs_sign_extractor c3-c2.der c3-c2.tbs c3-c2.sign <key-alg> <sign-alg> \n"); 
        printf("Available signature algorithms: sha-256, sha-384, sha-512, rsa \n");
        printf("Available key algorithms: ec-256, ec-384, ec-521, rsa \n");
        exit(1);
    }

    FILE* fp_der = fopen(argv[1], "r");

    if (fp_der == NULL){
        printf("Arquivo não encontrado.\n"); 
        exit(1);
    }

    FILE* fp_tbs = fopen(argv[2], "w");
    FILE* fp_sign = fopen(argv[3], "w");
    char * key_algorithm = argv[4];
    char * message_digest_alg  = argv[5];

    const char* oid_message_digest = message_alg_oid(message_digest_alg);

    // Ler arquivo binário DER e convertendo para string de hexadecimal 
    int c, i=0;
    while ((c = fgetc(fp_der)) != EOF) {
        // printf("%02x", c);
        snprintf(&der[i], sizeof(der), "%02x", c);
        i+=2;
    }

    uint16_t size_der = strlen(der);  
    
    // Extraindo e convertendo o tamanho da primeira sequência para comparar 
    // com o size_der. Cada caractere do DER é representado por 
    // 2 char na string (*2) + 8 caracteres do cabeçalho da primeira 
    // sequência(30820245)
    uint16_t read_size = (uint16_t)hextol(&der[4], 4) * 2 + 8;

    if (size_der == read_size){
        printf("DER OK. Tamanho total verificado: %d bytes\n", size_der/2);

        // Extraindo o tamanho da segunda sequência (TBSCertificate)
        uint16_t tbs_size = (uint16_t)hextol(&der[12], 4) * 2 + 8;  
        printf("TBS size: %d bytes\n", tbs_size/2);

        // Mostrando o TBSCertificate na tela em hexadecimal ...
        printf("TBSCertificate: \n%.*s\n", tbs_size, der + 8);
        printf("\n");
        // ... e salvando em binário no arquivo.
        // fprintf(fp_tbs, "%.*s", tbs_size, der + 8);  // Salva em string de hexadecimais.
        for (i=8;i<tbs_size+8;i+=2){
            fputc((int)hextol(&der[i], 2), fp_tbs);
        }
        // Verificação do início do tipo "BIT STRING", Tag Number: 03, sengundo ANS.1.
        // O BIT STRING é o tipo que identifica a assinatura feita sobre o TBSCertificate, 
        // está localizado logo depois do OID do algoritmo de assinatura (ecdsa_with_SHA512)
        char * sing_ptr;
        
        // Procura a primeira ocorrência de oid_message_digest
        sing_ptr = strstr (der,oid_message_digest);
        // Procura segunda ocorrência
        sing_ptr = strstr (sing_ptr+4,oid_message_digest);
        // Offset do OID, padrão para ec (10 bytes * 2) 
        // Offset do OID com RSA é 26               
        (strcmp(key_algorithm, "rsa")==0) ?  (sing_ptr = sing_ptr + 26) : sing_ptr = sing_ptr + 20;
        

        // O identificado de "BIT STRING" DEVE ser o Tag Number: 03.
        if (hextol(sing_ptr, 2) == 3){
            // Extraindo o tamanho do "BIT STRING" (assinatura)
            //sha-512 -> uint16_t sign_size = (uint16_t)hextol(sing_ptr+4, 2) * 2; 

            int bit_string = 0;
            
            // quando a chave EC possui curva P-521, existe 2 bytes a mais entre a tag bit_string e o oid
            // RSA não foi validado, está gerando falha de segmentação ao gravar a assinatura
            if((strcmp(key_algorithm, "ec-521")==0)){
                bit_string = 4;
            }else{
                bit_string = 2;
            }
            // FIXME RSA -> 0382020100, precisa ajustar pra pegar a assinatura quando chave é RSA
            uint16_t sign_size = (uint16_t)hextol(sing_ptr+bit_string, 2) * 2;  
            // Verifica se precisa remover leading-zeros da assinatura e
            // ajusta o ponteiro para o início exato da assinatura

            if (hextol(sing_ptr+6, 2) == 0){
                printf("Removendo os leading-zeros\n");
                sing_ptr = sing_ptr+8;
                sign_size -= 2;
            }else if (hextol(sing_ptr+8, 2) == 0){
                printf("Removendo os leading-zeros\n");
                sing_ptr = sing_ptr+10;
                sign_size -= 2;
            }
            else{
                sing_ptr = sing_ptr+6;
                sign_size -= 2;
            }
            // Mostrando a Assinatura na tela em hexadecimal ...
            printf("Assinatura: \n%.*s\n", sign_size, sing_ptr);
            // fprintf(fp_sign, "%.*s", sign_size, sing_ptr+6);
            // e salvando em binário no arquivo.
            for (i=0;i<sign_size;i+=2){
                fputc((int)hextol(&sing_ptr[i], 2), fp_sign);
            }

        } else{
            printf("Problema na extracao da assinatura\n");
        }

    }
    else{
        printf("Problema na verificação do arquivo");
    }

    fclose(fp_der);
    fclose(fp_tbs);
    fclose(fp_sign);
    return 0;
}