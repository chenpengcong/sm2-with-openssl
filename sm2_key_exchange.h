#ifndef SM2_KEY_EXCHANGE_H
#define SM2_KEY_EXCHANGE_H

#include <stddef.h>
#include <stdbool.h>
/**
 * 密钥交换, 输出共享密钥(实现参考GmSSL的sm2_exch.c)
 * 
 * @param is_initiator [IN] true:发起方 false:响应方
 * @param this_id [IN] 己方ID
 * @param this_id_len [IN] 己方ID长度
 * @param other_id [IN] 对方ID
 * @param other_id_len [IN] 对方ID长度
 * @param this_prikey [IN] 己方固定私钥, 长度32字节
 * @param this_pubkey [IN] 己方固定公钥, 格式:X(32字节) || y(32字节)
 * @param this_tmp_prikey [IN] 己方临时私钥, 长度32字节
 * @param this_tmp_pubkey_x [IN] 己方临时公钥x分量, 长度32字节
 * @param other_pubkey [IN] 对方固定公钥, 格式:X(32字节) || Y(32字节)
 * @param other_tmp_pubkey [IN] 对方临时公钥, 格式:X(32字节) || Y(32字节)
 * @param key [OUT] 交换得到的密钥
 * @param keylen [IN] 期望密钥长度
 * @return int 1:成功 0:失败
 */
int sm2_key_exchange(bool is_initiator, const unsigned char *this_id, size_t this_id_len,
    const unsigned char *other_id, size_t other_id_len,
    const unsigned char *this_prikey, const unsigned char *this_pubkey, 
    const unsigned char *this_tmp_prikey, const unsigned char *this_tmp_pubkey_x,
    const unsigned char *other_pubkey, const unsigned char *other_tmp_pubkey, 
    unsigned char *key, size_t keylen);

#endif /* SM2_KEY_EXCHANGE_H */