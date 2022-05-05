#include "rainbow-crypto.c"

int main(){
    unsigned char rnd_seed[48] = {0};
    byte_from_binfile( rnd_seed , 48 , "/dev/urandom" );
    printf("randombytes inited\n");
    uint8_t * pk = (uint8_t*)malloc( CRYPTO_PUBLICKEYBYTES );
    uint8_t * sk = (uint8_t*)malloc( CRYPTO_SECRETKEYBYTES );
    //uint8_t * signature = (uint8_t*)malloc( CRYPTO_BYTES );
    printf("pub: %d, pvt: %d \n",CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES);

    //uint8_t * msg = malloc(48);
    //byte_from_binfile( msg , 48 , "/dev/urandom" );
    unsigned char * msg = NULL;
    unsigned long long mlen = 0;
    byte_read_file( &msg , &mlen , "t2sign2" );
    printf("imported msg len: %d \n", mlen);
    uint8_t * psk = genkey(rnd_seed);
    memcpy( pk , psk , CRYPTO_PUBLICKEYBYTES );
    memcpy( sk  , psk + CRYPTO_PUBLICKEYBYTES , CRYPTO_SECRETKEYBYTES );
    printf("genkey completed\n");
    //printf(pk);
    //printf(sk);
    printf("mlen pub= %d \n", (int) (strlen((const char*)pk)));
    printf("mlen pvt= %d \n", (int) (strlen((const char*)sk)));

    uint8_t * s1 = sign(msg, mlen, sk);
    
    printf("sign completed\n");
    //int r = verify(msg, pk, signature, mlen);
    int r = verify(pk, s1, msg, mlen);
    //int r = verify1(pk, s1);
    printf("verify completed: %d \n", r);
    free( pk );
    free( sk );
    free( msg );
    //free( signature );
    return 0;
}

