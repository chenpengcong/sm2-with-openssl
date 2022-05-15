#ifndef SM2_ENCRYPT_DECRYPT_H
#define SM2_ENCRYPT_DECRYPT_H

#include <stddef.h>

/**
 * SM2加密
 * 
 * @param pub_key [IN]公钥数据:04 || X(32字节) || Y(32字节)
 * @param plain_text [IN]明文数据
 * @param plain_text_len [IN]明文数据长度
 * @param cipher_text [OUT]密文数据, ASN.1 DER编码
 * @param cipher_text_len [IN, OUT]密文数据长度
 * @return int 1:成功 0:失败
 */
int sm2_encrypt(const unsigned char *pubkey, size_t pubkey_len, const unsigned char *plain_text, 
    size_t plain_text_len, unsigned char *cipher_text, size_t *cipher_text_len);


/**
 * SM2解密
 * 
 * @param prikey [IN]私钥数据:Integer(32字节)
 * @param prikey_len [IN]私钥数据长度
 * @param cipher_text [IN]密文数据, ASN.1 DER编码
 * @param cipher_text_len [IN]密文长度
 * @param plain_text [OUT]明文
 * @param plain_text_len [OUT]明文长度
 * @return int 1:成功 0:失败
 */
int sm2_decrypt(const unsigned char *prikey, size_t prikey_len,
    const unsigned char *cipher_text, size_t cipher_text_len,
    unsigned char *plain_text, size_t *plain_text_len);

#endif /* SM2_ENCRYPT_DECRYPT_H */