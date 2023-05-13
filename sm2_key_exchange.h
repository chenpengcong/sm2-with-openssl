#ifndef SM2_KEY_EXCHANGE_H
#define SM2_KEY_EXCHANGE_H

#include <stddef.h>
#include <stdbool.h>
/**
 * @brief 密钥交换, 输出共享密钥(实现参考GmSSL的sm2_exch.c)
 * 
 * @param[in] is_initiator true：发起方 false：响应方
 * @param[in] this_id 己方ID
 * @param[in] this_id_len 己方ID长度
 * @param[in] other_id 对方ID
 * @param[in] other_id_len  对方ID长度
 * @param[in] this_prikey  己方固定私钥, 长度32字节
 * @param[in] this_pubkey  己方固定公钥, 格式：X(32字节) || y(32字节)
 * @param[in] this_tmp_prikey  己方临时私钥, 长度32字节
 * @param[in] this_tmp_pubkey_x 己方临时公钥x分量, 长度32字节
 * @param[in] other_pubkey 对方固定公钥, 格式：X(32字节) || Y(32字节)
 * @param[in] other_tmp_pubkey 对方临时公钥, 格式：X(32字节) || Y(32字节)
 * @param[out] key  交换得到的密钥
 * @param[in] keylen 期望密钥长度
 * @return int 结果码 
 *   1：成功 
 *   0：失败
 */
int sm2_key_exchange(bool is_initiator, const unsigned char *this_id, size_t this_id_len,
    const unsigned char *other_id, size_t other_id_len,
    const unsigned char *this_prikey, const unsigned char *this_pubkey, 
    const unsigned char *this_tmp_prikey, const unsigned char *this_tmp_pubkey_x,
    const unsigned char *other_pubkey, const unsigned char *other_tmp_pubkey, 
    unsigned char *key, size_t keylen);

#endif /* SM2_KEY_EXCHANGE_H */