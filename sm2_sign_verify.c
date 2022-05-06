#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
//#include "openssl/err.h" //有错误时可以使用ERR_print_errors_fp(stderr)来调试

/**
 * @brief 对待签数据原文进行SM2签名，包含预处理过程
 * 
 * @param message [IN]待签数据
 * @param message_len [IN]待签数据长度
 * @param signature [OUT] 签名结果, ASN.1 DER编码
 * @param signature_len [IN, OUT]签名结果长度, 值必须大于等于ASN.1编码后的签名值长度，建议>=72
 * @param pubkey_buff [IN]公钥数据：04 || X(32字节) || Y(32字节)
 * @param pubkey_len [IN]公钥数据长度
 * @param prikey_buff [IN]私钥数据：Integer(32字节)
 * @param prikey_len [IN]私钥数据长度
 * @param user_id [IN]用户ID
 * @param user_id_len [IN]用户ID长度
 * @return int 0：成功 其他：失败
 */
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
        printf("input parameters error\n");
        ret = -1;
        return ret;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if(ec_key == NULL) {
        printf("EC_KEY_new_by_curve_name NID_sm2 error\n");
        ret = -1;
        goto clean;
    }

    //将SM2公钥字节数组转成ECKEY，公钥数据：04 || X(32字节) || Y(32字节)
    if(EC_KEY_oct2key(ec_key, pubkey_buff, pubkey_len, NULL) != 1) {//经验证，如果不设置eckey的公钥，会导致EVP_DigestSignInit内部报segment fault，因为SM2签名预处理过程需要用到公钥
        printf("EC_KEY_oct2key error\n");
        ret = -1;
        goto clean;
    }

    //将SM2私钥字节数组转成ECKEY，私钥数据：Integer(32字节)
    if(EC_KEY_oct2priv(ec_key, prikey_buff, prikey_len) != 1) {
        printf("EC_KEY_oct2priv error\n");
        ret = -1;
        goto clean;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        printf("EVP_PKEY_new error\n");
        ret = -1;
        goto clean;
    }

    ret = EVP_PKEY_set1_EC_KEY(pkey, ec_key);
    if (ret != 1) {
        printf("EVP_PKEY_set1_EC_KEY error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }
    ret = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    if (ret != 1) {
        printf("EVP_PKEY_set_alias_type to EVP_PKEY_SM2 error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        printf("EVP_MD_CTX_new error\n");
        ret = -1;
        goto clean;
    }
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        printf("EVP_PKEY_CTX_new error\n");
        ret = -1;
        goto clean;
    }
    ret = EVP_PKEY_CTX_set1_id(pkey_ctx, user_id, user_id_len);//设置用户ID
    if (ret <= 0) {
        printf("EVP_PKEY_CTX_set1_id error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }
    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

    ret = EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey);
    if (ret != 1) {
        printf("EVP_DigestSignInit error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }

    ret = EVP_DigestSignUpdate(md_ctx, message, message_len);
    if (ret != 1){
        printf("EVP_DigestSignUpdate error, ret = %d", ret);
        ret = -1;
		goto clean;
	}

    ret = EVP_DigestSignFinal(md_ctx, signature, signature_len);//EVP_DigestSignFinal内部会判断signature_len是否足够存放ASN.1编码后的签名值，建议>=72
    if (ret != 1) {
        printf("EVP_DigestSignFinal error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }
    ret = 0;
    
clean:
    if (ec_key)
        EC_KEY_free(ec_key);
    if (pkey) 
        EVP_PKEY_free(pkey);
    if (pkey_ctx)
        EVP_PKEY_CTX_free(pkey_ctx);
    if (md_ctx)
        EVP_MD_CTX_free(md_ctx);
    return ret;
}


/**
 * @brief SM2验签，输入为被签名数据原文，包含预处理过程
 * 
 * @param message [IN]被签名数据
 * @param message_len [IN]被签名数据长度
 * @param signature [IN]签名值，ASN.1 DER编码
 * @param signature_len [IN]签名值长度
 * @param pubkey_buff [IN]公钥数据：04 || X(32字节) || Y(32字节)
 * @param pubkey_len [IN]公钥数据长度
 * @param user_id [IN]用户ID
 * @param user_id_len [IN]用户ID长度
 * @return int 0：成功 其他：失败
 */
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
        printf("input parameters error\n");
        ret = -1;
        return ret;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if(ec_key == NULL) {
        printf("EC_KEY_new_by_curve_name NID_sm2 error\n");
        ret = -1;
        goto clean;
    }

    ret = EC_KEY_oct2key(ec_key, pubkey_buff, pubkey_len, NULL);
    if(ret != 1)  {
        printf("EC_KEY_oct2key error\n");
        ret = -1;
        goto clean;
    }
    
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        printf("EVP_PKEY_new error\n");
        ret = -1;
        goto clean;
    }
    ret = EVP_PKEY_set1_EC_KEY(pkey, ec_key);
    if (ret != 1) {
        printf("EVP_PKEY_set1_EC_KEY error\n");
        ret = -1;
        goto clean;
    }
    ret = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    if (ret != 1) {
        printf("EVP_PKEY_set_alias_type to EVP_PKEY_SM2 error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        printf("EVP_MD_CTX_new error\n");
        ret = -1;
        goto clean;
    }
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        printf("EVP_PKEY_CTX_new error\n");
        ret = -1;
        goto clean;
    }
    ret = EVP_PKEY_CTX_set1_id(pkey_ctx, user_id, user_id_len);
    if (ret <= 0) {
        printf("EVP_PKEY_CTX_set1_id error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }
    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);
    
    ret = EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, pkey);
    if (ret != 1) {
        printf("EVP_DigestVerifyInit error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }
    ret = EVP_DigestVerifyUpdate(md_ctx, message, message_len);
    if (ret != 1) {
        printf("EVP_DigestVerifyUpdate error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }
    ret = EVP_DigestVerifyFinal(md_ctx, signature, signature_len);
    if (ret != 1) {
        printf("EVP_DigestVerifyFinal failed, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }
    ret = 0;

clean:
    if (ec_key)
        EC_KEY_free(ec_key);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (pkey_ctx)
        EVP_PKEY_CTX_free(pkey_ctx);
    if (md_ctx)
        EVP_MD_CTX_free(md_ctx);
    return ret;
}

/**
 * @brief SM2验签，输入为预处理2的杂凑值H，不包含预处理过程
 * 
 * @param digest [IN]杂凑值H
 * @param digest_len [IN]杂凑值长度
 * @param signature [IN]签名值，ASN.1 DER编码
 * @param signature_len [IN]签名值长度
 * @param pubkey_buff [IN]公钥数据
 * @param pubkey_len [IN]公钥数据长度
 * @return int 0：成功 其他：失败
 */
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
        printf("input parameters error\n");
        ret = -1;
        return ret;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if(ec_key == NULL) {
        printf("EC_KEY_new_by_curve_name NID_sm2 error\n");
        ret = -1;
        goto clean;
    }

    ret = EC_KEY_oct2key(ec_key, pubkey_buff, pubkey_len, NULL);
    if(ret != 1)  {
        printf("EC_KEY_oct2key error\n");
        ret = -1;
        goto clean;
    }
    
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        printf("EVP_PKEY_new error\n");
        ret = -1;
        goto clean;
    }
    ret = EVP_PKEY_set1_EC_KEY(pkey, ec_key);
    if (ret != 1) {
        printf("EVP_PKEY_set1_EC_KEY error\n");
        ret = -1;
        goto clean;
    }
    ret = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    if (ret != 1) {
        printf("EVP_PKEY_set_alias_type to EVP_PKEY_SM2 error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        printf("EVP_PKEY_CTX_new error\n");
        ret = -1;
        goto clean;
    }

    ret = EVP_PKEY_verify_init(pkey_ctx);
    if (ret != 1) {
        printf("EVP_PKEY_verify_init error, ret:%d\n", ret);
        ret = -1;
        goto clean;
    }

    ret = EVP_PKEY_verify(pkey_ctx, signature, signature_len, digest, digest_len);
    if (ret != 1) {
        printf("EVP_PKEY_verify failed, ret:%d\n", ret);
        ret = -1;
        goto clean;
    }
    ret = 0;

clean:
    if (ec_key)
        EC_KEY_free(ec_key);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (pkey_ctx)
        EVP_PKEY_CTX_free(pkey_ctx);
    return ret;
}

/**
 * @brief SM2签名，输入预处理2的杂凑值H，不包含预处理过程
 * 
 * @param digest [IN]杂凑值H
 * @param digest_len [IN]杂凑值长度
 * @param signature [OUT]签名结果，ASN.1 DER编码
 * @param signature_len [IN,OUT]签名结果长度, 值必须大于等于ASN.1编码后的签名值长度，建议>=72
 * @param pubkey_buff [IN]公钥数据：04 || X(32字节) || Y(32字节)
 * @param pubkey_len [IN]公钥数据长度
 * @param prikey_buff [IN]私钥数据：Integer(32字节)
 * @param prikey_len [IN]私钥数据长度
 * @return int 0：成功 其他：失败
 */
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
        printf("input parameters error\n");
        ret = -1;
        return ret;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if(ec_key == NULL) {
        printf("EC_KEY_new_by_curve_name NID_sm2 error\n");
        ret = -1;
        goto clean;
    }

    //将SM2私钥字节数组转成ECKEY，私钥数据：Integer(32字节)
    if(EC_KEY_oct2priv(ec_key, prikey_buff, prikey_len) != 1) {
        printf("EC_KEY_oct2priv error\n");
        ret = -1;
        goto clean;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        printf("EVP_PKEY_new error\n");
        ret = -1;
        goto clean;
    }

    ret = EVP_PKEY_set1_EC_KEY(pkey, ec_key);
    if (ret != 1) {
        printf("EVP_PKEY_set1_EC_KEY error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }
    ret = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    if (ret != 1) {
        printf("EVP_PKEY_set_alias_type to EVP_PKEY_SM2 error, ret = %d\n", ret);
        ret = -1;
        goto clean;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        printf("EVP_PKEY_CTX_new error\n");
        ret = -1;
        goto clean;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        printf("EVP_PKEY_CTX_new error\n");
        ret = -1;
        goto clean;
    }

    ret = EVP_PKEY_sign_init(pkey_ctx);
    if (ret != 1) {
        printf("EVP_PKEY_sign_init error, ret:%d\n", ret);
        ret = -1;
        goto clean;
    }

    ret = EVP_PKEY_sign(pkey_ctx, signature, signature_len, digest, digest_len);
    if (ret != 1) {
        printf("EVP_PKEY_sign error, ret:%d\n", ret);
        ret = -1;
        goto clean;
    }
    ret = 0;
    
clean:
    if (ec_key)
        EC_KEY_free(ec_key);
    if (pkey) 
        EVP_PKEY_free(pkey);
    if (pkey_ctx)
        EVP_PKEY_CTX_free(pkey_ctx);
    return ret;
}



/**
 * 使用《GMT 0003.5-2012 SM2椭圆曲线公钥密码算法第5部分：参数定义》附录A的签名示例数据来验证
 * 待签名消息：message digest，对应ASCII码的16进制表示：6D65737361676520646967657374
 * 私钥： 3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8
 * 公钥x：09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020
 * 公钥y：CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13
 * 用户ID：16进制表示 31323334 35363738 31323334 35363738
 * 
 * 杂凑值H：F0B43E94 BA45ACCA ACE692ED 534382EB 17E6AB5A 19CE7B31 F4486FDF C0D28640
 * 签名(r, s)
 * 值r: F5A03B06 48D2C463 0EEAC513 E1BB81A1 5944DA38 27D5B741 43AC7EAC EEE720B3
 * 值s：B1B6AA29 DF212FD8 763182BC 0D421CA1 BB9038FD 1F7F42D4 840B69C4 85BBC1AA
 */
static const unsigned char s_message[] = {
    0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74
};

static const unsigned char s_prikey_buff[] = {
    0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1, 0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3, 0x9F, 0x95, 
    0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A, 0x42, 0xFB, 0x81, 0xEF, 0x4D, 0xF7, 0xC5, 0xB8
};

static const unsigned char s_pubkey_buff[] = {
    //04：非压缩格式
    0x04, 
    //公钥x
    0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6, 
    0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
    //公钥y
    0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60, 
    0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13
};

static const unsigned char s_user_id[] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

static const unsigned char s_digest_H[] = {
    0XF0, 0XB4, 0X3E, 0X94, 0XBA, 0X45, 0XAC, 0XCA, 0XAC, 0XE6, 0X92, 0XED, 0X53, 0X43, 0X82, 0XEB, 
    0X17, 0XE6, 0XAB, 0X5A, 0X19, 0XCE, 0X7B, 0X31, 0XF4, 0X48, 0X6F, 0XDF, 0XC0, 0XD2, 0X86, 0X40
};

static const unsigned char s_signature[] = {
    //Tag Len
    0x30, 0x46, 
    //Tag Len
    0x02, 0x21, 
    //签名值r，由于ASN.1编码Integer时最高bit为1表示负数，而r实际是正整数，所以添加0x00表示正数
    0x00,
    0xF5, 0xA0, 0x3B, 0x06, 0x48, 0xD2, 0xC4, 0x63, 0x0E, 0xEA, 0xC5, 0x13, 0xE1, 0xBB, 0x81, 0xA1,
    0x59, 0x44, 0xDA, 0x38, 0x27, 0xD5, 0xB7, 0x41, 0x43, 0xAC, 0x7E, 0xAC, 0xEE, 0xE7, 0x20, 0xB3,
    //Tag Len
    0x02, 0x21,
    //签名值s，添加0x00原因同r
    0x00,
    0xB1, 0xB6, 0xAA, 0x29, 0xDF, 0x21, 0x2F, 0xD8, 0x76, 0x31, 0x82, 0xBC, 0x0D, 0x42, 0x1C, 0xA1, 
    0xBB, 0x90, 0x38, 0xFD, 0x1F, 0x7F, 0x42, 0xD4, 0x84, 0x0B, 0x69, 0xC4, 0x85, 0xBB, 0xC1, 0xAA
};


void test_sm2_digest_verify()
{
    printf("\n/*************test_sm2_digest_verify*************/\n");
    int res = sm2_digest_verify(s_message, sizeof(s_message), 
        s_signature, sizeof(s_signature),
        s_pubkey_buff, sizeof(s_pubkey_buff),
        s_user_id, sizeof(s_user_id));

    if (res != 0) {
        printf("sm2_digest_verify() failed to verify the signature defined in GMT0003.5-2012!\n");
        return;
    } else {
        printf("sm2_digest_verify() verify the signature defined in GMT0003.5-2012 successfully!\n");
    }
}

void test_sm2_digest_sign_verify()
{
    printf("\n/*************test_sm2_digest_sign_verify*************/\n");
    unsigned char signature[72];
    size_t signature_len = sizeof(signature);
    size_t i;

    int res = sm2_digest_sign(s_message, sizeof(s_message), 
        signature, &signature_len,
        s_pubkey_buff, sizeof(s_pubkey_buff),
        s_prikey_buff, sizeof(s_prikey_buff),
        s_user_id, sizeof(s_user_id));
    
    if (res != 0) {
        printf("sign with sm2 error!\n");
        return;
    } else {
        printf("sign with sm2 successfully!\n");
        printf("signature len:%zu\n", signature_len);
        printf("signature value(ASN.1 DER encoding):");
        for (i = 0; i < signature_len;i++) {
            printf("%02x", signature[i]);
        }
        printf("\n");
    }
    res = sm2_digest_verify(s_message, sizeof(s_message), 
        signature, signature_len,
        s_pubkey_buff, sizeof(s_pubkey_buff),
        s_user_id, sizeof(s_user_id));
    if (res != 0) {
        printf("verify error!\n");
        return;
    } else {
        printf("verify successfully!\n");
    }
}

void test_sm2_verify()
{
    printf("\n/*************test_sm2_verify*************/\n");
    int res = sm2_verify(s_digest_H, sizeof(s_digest_H), 
        s_signature, sizeof(s_signature),
        s_pubkey_buff, sizeof(s_pubkey_buff));
    if (res != 0) {
        printf("sm2_verify() failed to verify the signature defined in GMT0003.5-2012!\n");
        return;
    } else {
        printf("sm2_verify() verify the signature defined in GMT0003.5-2012 successfully!\n");
    }
}

void test_sm2_sign_verify()
{
    printf("\n/*************test_sm2_sign_verify*************/\n");
    unsigned char signature[72];
    size_t signature_len = sizeof(signature);
    size_t i;
    int res = sm2_sign(s_digest_H, sizeof(s_digest_H), 
        signature, &signature_len,
        s_pubkey_buff, sizeof(s_pubkey_buff),
        s_prikey_buff, sizeof(s_prikey_buff));
        
    if (res != 0) {
        printf("sign with sm2 error!\n");
        return;
    } else {
        printf("sign with sm2 successfully!\n");
        printf("signature len:%zu\n", signature_len);
        printf("signature value(ASN.1 DER encoding):");
        for (i = 0; i < signature_len;i++) {
            printf("%02x", signature[i]);
        }
        printf("\n");
    }
    res = sm2_verify(s_digest_H, sizeof(s_digest_H), 
        signature, signature_len,
        s_pubkey_buff, sizeof(s_pubkey_buff));
    if (res != 0) {
        printf("verify error!\n");
        return;
    } else {
        printf("verify successfully!\n");
    }
}

int main(int argc, char **argv)
{
    test_sm2_digest_verify();
    test_sm2_digest_sign_verify();
    test_sm2_verify();
    test_sm2_sign_verify();
    return 0;
}
