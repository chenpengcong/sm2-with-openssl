#include "sm2_encrypt_decrypt.h"
#include "debug.h"
#include "stdlib.h"
#include <openssl/evp.h>
#include <openssl/ec.h>

int sm2_encrypt(const unsigned char *pubkey, size_t pubkey_len, const unsigned char *plain_text, 
    size_t plain_text_len, unsigned char *cipher_text, size_t *cipher_text_len) 
{
    int ret = 0;
    EC_KEY *ec_key;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey;

    if ((pubkey == NULL) || (pubkey_len != 65)
        || (plain_text == NULL) || (plain_text_len < 1)
        || (cipher_text_len == NULL)) {
        TRACE("%s\n", "input parameter error");
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if(ec_key == NULL) {
        TRACE("%s\n", "EC_KEY_new_by_curve_name NID_sm2 error");
        goto end;
    }
    /* 将SM2公钥字节数组转成ECKEY，公钥数据：04 || X(32字节) || Y(32字节) */
    if(!EC_KEY_oct2key(ec_key, pubkey, pubkey_len, NULL)) {
        TRACE("%s\n", "EC_KEY_oct2key error");
        goto end;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        TRACE("%s\n", "EVP_PKEY_new error");
        goto end;
    }

    if (!EVP_PKEY_set1_EC_KEY(pkey, ec_key)) {
        TRACE("%s\n", "EVP_PKEY_set1_EC_KEY error");
        goto end;
    }

    if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) {
        TRACE("%s\n", "EVP_PKEY_set_alias_type to EVP_PKEY_SM2 error");
        goto end;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        TRACE("%s\n", "EVP_PKEY_CTX_new error");
        goto end;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        TRACE("%s\n", "EVP_PKEY_encrypt_init error");
        goto end;
    }

     if (EVP_PKEY_encrypt(ctx, cipher_text, cipher_text_len, plain_text, plain_text_len) <= 0) {
        TRACE("%s\n", "EVP_PKEY_encrypt error");
        goto end;
     }
    ret = 1;
end:
    EC_KEY_free(ec_key);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ret;
}



int sm2_decrypt(const unsigned char *prikey, size_t prikey_len,
    const unsigned char *cipher_text, size_t cipher_text_len,
    unsigned char *plain_text, size_t *plain_text_len)
{
    int ret = 0;
    EC_KEY *ec_key;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *ctx;
    if ((prikey == NULL) || (prikey_len < 1)
        || (cipher_text == NULL) || (cipher_text_len < 1)
        || (plain_text_len == NULL)) {
        TRACE("%s\n", "input parameter error");
        return ret;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if(ec_key == NULL) {
        TRACE("%s\n", "EC_KEY_new_by_curve_name NID_sm2 error");
        goto end;
    }
    /* 将SM2私钥字节数组转成ECKEY，私钥数据：Integer(32字节) */
    if(!EC_KEY_oct2priv(ec_key, prikey, prikey_len)) {
        TRACE("%s\n", "EC_KEY_oct2priv error");
        goto end;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        TRACE("%s\n", "EVP_PKEY_new error");
        goto end;
    }

    if (!EVP_PKEY_set1_EC_KEY(pkey, ec_key)) {
        TRACE("%s\n", "EVP_PKEY_set1_EC_KEY error");
        goto end;
    }

    if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) {
        TRACE("%s\n", "EVP_PKEY_set_alias_type to EVP_PKEY_SM2 error");
        goto end;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        TRACE("%s\n", "EVP_PKEY_CTX_new error");
        goto end;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        TRACE("%s\n", "EVP_PKEY_decrypt_init error");
        goto end;
    }

    if (EVP_PKEY_decrypt(ctx, plain_text, plain_text_len, cipher_text, cipher_text_len) <= 0) {
        TRACE("%s\n", "EVP_PKEY_decrypt error");
        goto end;
    }

    ret = 1;
end:
    EC_KEY_free(ec_key);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ret;
}