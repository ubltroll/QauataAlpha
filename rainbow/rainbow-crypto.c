///  @file rainbow.c
///  @brief Runtime lib for rainbow supports.
///

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "rainbow_config.h"

#include "utils.h"

#include "rng.h"

#include "api.h"

uint8_t * genkey(uint8_t * rnd_seed)
{
    uint8_t * pk = (uint8_t*)malloc( CRYPTO_PUBLICKEYBYTES );
    uint8_t * sk = (uint8_t*)malloc( CRYPTO_SECRETKEYBYTES );
    randombytes_init( rnd_seed , NULL , 256 );
    crypto_sign_keypair( pk, sk );
    uint8_t * psk = malloc( CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES );
    memcpy( psk , pk , CRYPTO_PUBLICKEYBYTES );
    memcpy( psk + CRYPTO_PUBLICKEYBYTES , sk , CRYPTO_SECRETKEYBYTES );
    free( pk );
    free( sk );
    return psk;
}

uint8_t * sign(uint8_t * msg, unsigned long long mlen, uint8_t * _sk)
{
    uint8_t * signature = malloc( mlen + CRYPTO_BYTES );
    unsigned long long smlen = 0;
    crypto_sign( signature, &smlen, msg , mlen , _sk );

    uint8_t * _sign = malloc( CRYPTO_BYTES );
    memcpy(_sign, signature + mlen , CRYPTO_BYTES );

    free( signature );

    return _sign;
}


int verify(uint8_t * pk, uint8_t * _sign, uint8_t * msg, unsigned long long mlen)
{

    int r;

    unsigned char * signature = malloc( mlen + CRYPTO_BYTES );
    if( NULL == signature ) {
        //alloc memory for signature buffer fail
        return -1;
    }
    memcpy( signature , msg , mlen );
    
    memcpy( signature + mlen , _sign , CRYPTO_BYTES );
    
    r = crypto_sign_open( msg , &mlen , signature , mlen + CRYPTO_BYTES , pk );

    if( 0 == r ) {
        //correctly verified.
        return 1;
    } else {
        //verification fails.
        return 0;
    }
}

