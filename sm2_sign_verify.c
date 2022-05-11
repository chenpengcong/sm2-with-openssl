#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "sm2_sign_verify.h"
#include "debug.h"

/* tip: 有错误时可以使用<openssl/err.h>的ERR_print_errors_fp(stderr)来调试 */

int sm2_digest_sign(const unsigned char *message, size_t message_len, 
    unsigned char *signature, size_t *signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len,
    const unsigned char *prikey_buff, size_t prikey_len,
    const unsigned char *user_id, size_t user_id_len
)
{
    int ret = 0;
    EC_KEY *ec_key = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;

    if (message == NULL || message_len < 1 
        || signature == NULL || *signature_len < 72
        || pubkey_buff == NULL || pubkey_len != 65
        || prikey_buff == NULL || prikey_len != 32
        || user_id == NULL || user_id_len < 1
    ) {
        TRACE("%s\n", "input parameters error");
        return ret;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if(ec_key == NULL) {
        TRACE("%s\n", "EC_KEY_new_by_curve_name NID_sm2 error");
        goto end;
    }

    /**
     * 将SM2公钥字节数组转成ECKEY，公钥数据：04 || X(32字节) || Y(32字节)
     * 经验证，如果不设置eckey的公钥，会导致EVP_DigestSignInit内部报segment fault，因为SM2签名预处理过程需要用到公钥
     */
    if(!EC_KEY_oct2key(ec_key, pubkey_buff, pubkey_len, NULL)) {
        TRACE("%s\n", "EC_KEY_oct2key error");
        goto end;
    }

    /* 将SM2私钥字节数组转成ECKEY，私钥数据：Integer(32字节) */
    if(!EC_KEY_oct2priv(ec_key, prikey_buff, prikey_len)) {
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

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        TRACE("%s\n", "EVP_MD_CTX_new error");
        goto end;
    }
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        TRACE("%s\n", "EVP_PKEY_CTX_new error");
        goto end;
    }
    /* 设置用户ID */
    if (EVP_PKEY_CTX_set1_id(pkey_ctx, user_id, user_id_len) <= 0) {
        TRACE("%s\n", "EVP_PKEY_CTX_set1_id error");
        goto end;
    }

    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

    if (!EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey)) {
        TRACE("%s\n", "EVP_DigestSignInit error");
        goto end;
    }

    if (!EVP_DigestSignUpdate(md_ctx, message, message_len)){
        TRACE("%s\n", "EVP_DigestSignUpdate error");
		goto end;
	}

    /* EVP_DigestSignFinal内部会判断signature_len是否足够存放ASN.1编码后的签名值，建议>=72 */
    if (!EVP_DigestSignFinal(md_ctx, signature, signature_len)) {
        TRACE("%s\n", "EVP_DigestSignFinal error");
        goto end;
    }
    ret = 1;

end:
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_MD_CTX_free(md_ctx);
    return ret;
}



int sm2_digest_verify(const unsigned char *message, size_t message_len, 
    const unsigned char *signature, size_t signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len,
    const unsigned char *user_id, size_t user_id_len
)
{
    int ret = 0;
    EC_KEY *ec_key = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;

    if (message == NULL || message_len == 0 
        || signature == NULL || signature_len == 0
        || pubkey_buff == NULL || pubkey_len != 65
        || user_id == NULL || user_id_len < 1
    ) {
        TRACE("%s\n", "input parameters error");
        return ret;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if(ec_key == NULL) {
        TRACE("%s\n", "EC_KEY_new_by_curve_name NID_sm2 error");
        goto end;
    }

    if(!EC_KEY_oct2key(ec_key, pubkey_buff, pubkey_len, NULL))  {
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

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        TRACE("%s\n", "EVP_MD_CTX_new error");
        goto end;
    }
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        TRACE("%s\n", "EVP_PKEY_CTX_new error");
        goto end;
    }

    if (EVP_PKEY_CTX_set1_id(pkey_ctx, user_id, user_id_len) <= 0) {
        TRACE("%s\n", "EVP_PKEY_CTX_set1_id error");
        goto end;
    }
    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);
    
    if (!EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, pkey)) {
        TRACE("%s\n", "EVP_DigestVerifyInit error");
        goto end;
    }

    if (!EVP_DigestVerifyUpdate(md_ctx, message, message_len)) {
        TRACE("%s\n", "EVP_DigestVerifyUpdate error");
        goto end;
    }

    if (!EVP_DigestVerifyFinal(md_ctx, signature, signature_len)) {
        TRACE("%s\n", "EVP_DigestVerifyFinal error");
        goto end;
    }
    ret = 1;

end:
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_MD_CTX_free(md_ctx);
    return ret;
}


int sm2_verify(const unsigned char *digest, size_t digest_len, 
    const unsigned char *signature, size_t signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len
)
{
    int ret = 0;
    EC_KEY *ec_key = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    if (digest == NULL || digest_len != 32 
        || signature == NULL || signature_len == 0
        || pubkey_buff == NULL || pubkey_len != 65
    ) {
        TRACE("%s\n", "input parameters error");
        return ret;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if(ec_key == NULL) {
        TRACE("%s\n", "EC_KEY_new_by_curve_name NID_sm2 error");
        goto end;
    }

 
    if(!EC_KEY_oct2key(ec_key, pubkey_buff, pubkey_len, NULL))  {
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

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        TRACE("%s\n", "EVP_PKEY_CTX_new error");
        goto end;
    }

    if (!EVP_PKEY_verify_init(pkey_ctx)) {
        TRACE("%s\n", "EVP_PKEY_verify_init error");
        goto end;
    }

    if (!EVP_PKEY_verify(pkey_ctx, signature, signature_len, digest, digest_len)) {
        TRACE("%s\n", "EVP_PKEY_verify error");
        goto end;
    }
    ret = 1;
end:
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    return ret;
}


int sm2_sign(const unsigned char *digest, size_t digest_len, 
    unsigned char *signature, size_t *signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len,
    const unsigned char *prikey_buff, size_t prikey_len
)
{
    int ret = 0;
    EC_KEY *ec_key = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    if (digest == NULL || digest_len != 32 
        || signature == NULL || *signature_len < 72
        || pubkey_buff == NULL || pubkey_len != 65
        || prikey_buff == NULL || prikey_len != 32
    ) {
        TRACE("%s\n", "input parameters error");
        return ret;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if(ec_key == NULL) {
        TRACE("%s\n", "EC_KEY_new_by_curve_name NID_sm2 error");
        goto end;
    }

    /* 将SM2私钥字节数组转成ECKEY，私钥数据：Integer(32字节) */
    if(!EC_KEY_oct2priv(ec_key, prikey_buff, prikey_len)) {
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

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        TRACE("%s\n", "EVP_PKEY_CTX_new error");
        goto end;
    }

    if (!EVP_PKEY_sign_init(pkey_ctx)) {
        TRACE("%s\n", "EVP_PKEY_sign_init error");
        goto end;
    }

    if (!EVP_PKEY_sign(pkey_ctx, signature, signature_len, digest, digest_len)) {
        TRACE("%s\n", "EVP_PKEY_sign error");
        goto end;
    }
    ret = 1;
    
end:
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    return ret;
}