#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const char oid_p_521[] = "301006072a8648ce3d020106052b81040023"; 
const char oid_p_384[] = "301006072a8648ce3d020106052b81040022";
const char oid_p_256[] = "301306072a8648ce3d020106082a8648ce3d030107";
const char oid_p_rsa[] = "300d06092a864886f70d0101010500";
char der[1200]; 

// Fonte: https://community.letsencrypt.org/t/when-choosing-an-elliptic-curve-look-for-a-safe-curve/161837
// For P‐256 keys, 301306072a8648ce3d020106082a8648ce3d030107.
// For P‐384 keys, 301006072a8648ce3d020106052b81040022.
// For P‐521 keys, 301006072a8648ce3d020106052b81040023.

// Fonte: https://letsencrypt.org/documents/isrg-cp-v2.5/
// For RSA keys, 300d06092a864886f70d0101010500

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

    if(strcmp(alg, "ec-256")==0){
        return oid_p_256;
    }else if (strcmp(alg, "ec-384")==0){
       return oid_p_384; 
    }else if (strcmp(alg, "ec-521")==0){
       return oid_p_521; 
    }else if (strcmp(alg, "rsa")==0){
       return oid_p_rsa; 
    }
    else {
        return "Valor inválido";
    }
}

int main(int argc, char *argv[]){

    if(argc!=4){
        printf("Usage example: ./pub_key_extractor c2-c1.der c2-pub.der <key-alg> \n"); 
        printf("Available key algorithms: ec-256, ec-384, ec-521, rsa \n");
        exit(1);
    }

    FILE* fp_der = fopen(argv[1], "r");
    char * key_algorithm = argv[3];

    if (fp_der == NULL){
        printf("Arquivo não encontrado.\n"); 
        exit(1);
    }

    // Ler arquivo binário DER e convertendo para string de hexadecimal 
    int c, i=0;
    while ((c = fgetc(fp_der)) != EOF) {
        // printf("%02x", c);
        snprintf(&der[i], sizeof(der), "%02x", c);
        i+=2;
    }
    
    fclose(fp_der);


    FILE* fp_key = fopen(argv[2], "w");

    uint16_t size_der = strlen(der);  
    
    // Extraindo e convertendo o tamanho da primeira sequência para comparar 
    // com o size_der. Cada caractere do DER é representado por 
    // 2 char na string (*2) + 8 caracteres do cabeçalho da primeira 
    // sequência(30820245)
    uint16_t read_size = (uint16_t)hextol(&der[4], 4) * 2 + 8;
    
    if (size_der == read_size){
        printf("DER OK. Tamanho total verificado: %d bytes\n", size_der/2);

        // Procura a ocorrência do identificador (OID) da chave 
        // - p_521 = 301006072a8648ce3d020106052b81040023
        char * key_ptr;
        const char* oid_message_digest = message_alg_oid(key_algorithm);
        key_ptr = strstr (der, oid_message_digest);
        // Offset para o início da sequência, 3 bytes * 2 antes do OID, para EC-512, ec-256/384 é 2 bytes * 2, rsa 4 * 2
        int offset_start = 0;
            if((strcmp(key_algorithm, "ec-521")==0)){
                offset_start = 6;
            }else if ((strcmp(key_algorithm, "rsa")==0)){
                offset_start = 8;
            }
            else{
                offset_start = 4;
            }
        key_ptr = key_ptr - offset_start;
        
        printf("Chave: \n%s\n", key_ptr);
        printf("\n");
        // O identificador da sequencia deve ser 0x30.
        if (hextol(key_ptr, 2) == 0x30){
            int bit_string = 0;
            //quando chave ec possui curva ec-521, possui 2 bytes a mais
            if((strcmp(key_algorithm, "ec-521")==0)){
                bit_string = 4;
            }else{
                bit_string = 2;
            }
            //Extraindo o tamanho do sequencia.
            // FIXME RSA -> 30820122, precisa ajustar pra pegar a chave quando chave é RSA
            uint16_t seq_size = (uint16_t)hextol(key_ptr+bit_string, 2) * 2 + 6;  

            // Mostrando a Assinatura na tela em hexadecimal ...
            printf("Chave: \n%.*s\n", seq_size, key_ptr);
            // fprintf(fp_sign, "%.*s", sign_size, sing_ptr+6);

            // e salvando em binário no arquivo.
            for (i=0;i<seq_size;i+=2){
                fputc((int)hextol(&key_ptr[i], 2), fp_key);
            }


        } else{
            printf("Problema na extração da chave\n");
        }

    }
    else{
        printf("Problema na verificação do arquivo");
    }

    
    fclose(fp_key);

    return 0;
}
