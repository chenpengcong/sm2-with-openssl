#ifndef SM2_SIGN_VERIFY_H
#define SM2_SIGN_VERIFY_H

#include <stddef.h>

/**
 * SM2签名，输入为待签名数据原文，包含预处理过程
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
 * @return int 1：成功 0：失败
 */
int sm2_digest_sign(const unsigned char *message, size_t message_len, 
    unsigned char *signature, size_t *signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len,
    const unsigned char *prikey_buff, size_t prikey_len,
    const unsigned char *user_id, size_t user_id_len
);

/**
 * SM2验签，输入为被签名数据原文，包含预处理过程
 * 
 * @param message [IN]被签名数据
 * @param message_len [IN]被签名数据长度
 * @param signature [IN]签名值，ASN.1 DER编码
 * @param signature_len [IN]签名值长度
 * @param pubkey_buff [IN]公钥数据：04 || X(32字节) || Y(32字节)
 * @param pubkey_len [IN]公钥数据长度
 * @param user_id [IN]用户ID
 * @param user_id_len [IN]用户ID长度
 * @return int 1：成功 0：失败
 */
int sm2_digest_verify(const unsigned char *message, size_t message_len, 
    const unsigned char *signature, size_t signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len,
    const unsigned char *user_id, size_t user_id_len
);

/**
 * SM2签名，输入预处理2的杂凑值H，不包含预处理过程
 * 
 * @param digest [IN]杂凑值H
 * @param digest_len [IN]杂凑值长度
 * @param signature [OUT]签名结果，ASN.1 DER编码
 * @param signature_len [IN,OUT]签名结果长度, 值必须大于等于ASN.1编码后的签名值长度，建议>=72
 * @param pubkey_buff [IN]公钥数据：04 || X(32字节) || Y(32字节)
 * @param pubkey_len [IN]公钥数据长度
 * @param prikey_buff [IN]私钥数据：Integer(32字节)
 * @param prikey_len [IN]私钥数据长度
 * @return int 1：成功 0：失败
 */
int sm2_sign(const unsigned char *digest, size_t digest_len, 
    unsigned char *signature, size_t *signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len,
    const unsigned char *prikey_buff, size_t prikey_len
);

/**
 * SM2验签，输入为预处理2的杂凑值H，不包含预处理过程
 * 
 * @param digest [IN]杂凑值H
 * @param digest_len [IN]杂凑值长度
 * @param signature [IN]签名值，ASN.1 DER编码
 * @param signature_len [IN]签名值长度
 * @param pubkey_buff [IN]公钥数据
 * @param pubkey_len [IN]公钥数据长度
 * @return int 1：成功 0：失败
 */
int sm2_verify(const unsigned char *digest, size_t digest_len, 
    const unsigned char *signature, size_t signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len
);


#endif /* SM2_SIGN_VERIFY_H */