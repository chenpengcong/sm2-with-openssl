#ifndef SM2_ENCRYPT_DECRYPT_H
#define SM2_ENCRYPT_DECRYPT_H

#include <stddef.h>

/**
 * @brief SM2加密
 * 
 * @param[in] pub_key 公钥数据：04 || X(32字节) || Y(32字节)
 * @param[in] plain_text 明文数据
 * @param[in] plain_text_len 明文数据长度
 * @param[out] cipher_text 密文数据, ASN.1 DER编码。如果cipher_text为NULL，cipher_text_len参数将会返回密文的可能最大长度
 * @param[in,out] cipher_text_len 密文数据长度
 * @return int 结果码
 *   1：成功 
 *   0：失败
 */
int sm2_encrypt(const unsigned char *pubkey, size_t pubkey_len, const unsigned char *plain_text, 
    size_t plain_text_len, unsigned char *cipher_text, size_t *cipher_text_len);


/**
 * @brief SM2解密
 * 
 * @param[in] prikey 私钥数据：Integer(32字节)
 * @param[in] prikey_len 私钥数据长度
 * @param[in] cipher_text 密文数据, ASN.1 DER编码
 * @param[in] cipher_text_len 密文长度
 * @param[out] plain_text 明文，如果plain_text为NULL，plain_text_len参数将会返回明文的可能最大长度
 * @param[out] plain_text_len 明文长度
 * @return int 结果码
 *   1：成功
 *   0：失败
 */
int sm2_decrypt(const unsigned char *prikey, size_t prikey_len,
    const unsigned char *cipher_text, size_t cipher_text_len,
    unsigned char *plain_text, size_t *plain_text_len);

#endif /* SM2_ENCRYPT_DECRYPT_H */