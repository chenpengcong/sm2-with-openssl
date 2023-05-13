#ifndef SM2_SIGN_VERIFY_H
#define SM2_SIGN_VERIFY_H

#include <stddef.h>

/**
 * @brief SM2签名，输入为待签名数据原文，包含预处理过程
 * 
 * @param[in] message 待签数据
 * @param[in] message_len 待签数据长度
 * @param[out] signature 签名值，ASN.1 DER编码。如果signature为NULL，signature_len参数将会返回签名值的可能最大长度
 * @param[in,out] signature_len 输入时表示signature缓冲区长度，输出时表示签名值长度
 * @param[in] pubkey_buff 公钥数据：04 || X(32字节) || Y(32字节)
 * @param[in] pubkey_len 公钥数据长度
 * @param[in] prikey_buff 私钥数据：Integer(32字节)
 * @param[in] prikey_len 私钥数据长度
 * @param[in] user_id 用户ID
 * @param[in] user_id_len 用户ID长度
 * @return int 结果码
 *   1：成功 
 *   0：失败
 */
int sm2_digest_sign(const unsigned char *message, size_t message_len, 
    unsigned char *signature, size_t *signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len,
    const unsigned char *prikey_buff, size_t prikey_len,
    const unsigned char *user_id, size_t user_id_len
);

/**
 * @brief SM2验签，输入为被签名数据原文，包含预处理过程
 * 
 * @param[in] message 被签名数据
 * @param[in] message_len 被签名数据长度
 * @param[in] signature 签名值，ASN.1 DER编码
 * @param[in] signature_len 签名值长度
 * @param[in] pubkey_buff 公钥数据：04 || X(32字节) || Y(32字节)
 * @param[in] pubkey_len 公钥数据长度
 * @param[in] user_id 用户ID
 * @param[in] user_id_len 用户ID长度
 * @return int 结果码
 *   1：成功 
 *   0：失败
 */
int sm2_digest_verify(const unsigned char *message, size_t message_len, 
    const unsigned char *signature, size_t signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len,
    const unsigned char *user_id, size_t user_id_len
);

/**
 * @brief SM2签名，输入预处理2的杂凑值H，不包含预处理过程
 * 
 * @param[in] digest 杂凑值H
 * @param[in] digest_len 杂凑值长度
 * @param[out] signature 签名值，ASN.1 DER编码。如果signature为NULL，signature_len参数将会返回签名值的可能最大长度
 * @param[in,out] signature_len 输入时表示signature缓冲区长度，输出时表示签名值长度
 * @param[in] pubkey_buff 公钥数据：04 || X(32字节) || Y(32字节)
 * @param[in] pubkey_len 公钥数据长度
 * @param[in] prikey_buff 私钥数据：Integer(32字节)
 * @param[in] prikey_len 私钥数据长度
 * @return int 结果码
 *   1：成功
 *   0：失败
 */
int sm2_sign(const unsigned char *digest, size_t digest_len, 
    unsigned char *signature, size_t *signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len,
    const unsigned char *prikey_buff, size_t prikey_len
);

/**
 * @brief SM2验签，输入为预处理2的杂凑值H，不包含预处理过程
 * 
 * @param[in] digest 杂凑值H
 * @param[in] digest_len 杂凑值长度
 * @param[in] signature 签名值，ASN.1 DER编码
 * @param[in] signature_len 签名值长度
 * @param[in] pubkey_buff 公钥数据
 * @param[in] pubkey_len 公钥数据长度
 * @return int 结果码
 *   1：成功 
 *   0：失败
 */
int sm2_verify(const unsigned char *digest, size_t digest_len, 
    const unsigned char *signature, size_t signature_len,
    const unsigned char *pubkey_buff, size_t pubkey_len
);


/**
 * @brief 将DER编码的SM2签名值转换成64字节的编码格式
 * 
 * @param[in] der der编码的签名值
 * @param[in] der_len der编码的签名值长度
 * @param[out] raw 64字节编码的签名值
 * @return int 结果码
 *   1：成功 
 *   0：失败
 */
int sm2_sig_der2raw(const unsigned char *der, size_t der_len, unsigned char *raw);

/**
 * @brief 将64字节编码的SM2签名值转换成DER编码格式
 * 
 * @param[in] raw 64字节编码的签名值
 * @param[out] der der编码的签名值
 * @param[in,out] der_len 输入时表示der缓冲区的长度，输出时表示der编码的签名值长度
 * @return int 结果码
 *   1：成功 
 *   0：失败
 */
int sm2_sig_raw2der(const unsigned char *raw, unsigned char *der, size_t *der_len);
#endif /* SM2_SIGN_VERIFY_H */