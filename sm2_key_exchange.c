#include <openssl/bn.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <string.h>
#include "debug.h"
#include "sm2_key_exchange.h"

/**
 * 计算Z值(实现参考OpenSSL1.1.1的sm2_sign.c)
 * 公式：Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
 * 
 * @param out [OUT] 32字节Z值
 * @param id [IN] ID
 * @param id_len [IN] ID长度
 * @param key [IN] 设置过公钥的EC_KEY
 * @return int 1：成功, 0：失败
 */
int sm2_compute_z_digest(unsigned char *out, const unsigned char *id,
    const size_t id_len, EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *hash = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *xG = NULL;
    BIGNUM *yG = NULL;
    BIGNUM *xA = NULL;
    BIGNUM *yA = NULL;
    int p_bytes = 0;
    unsigned char *buf = NULL;
    unsigned short entl = 0;
    unsigned char e_byte = 0;

    hash = EVP_MD_CTX_new();
    ctx = BN_CTX_new();
    if (hash == NULL || ctx == NULL) {
        TRACE("%s\n", "EVP_MD_CTX_new or BN_CTX_new error");
        goto end;
    }

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);

    if (yA == NULL) {
        TRACE("%s\n", "BN_CTX_get error");
        goto end;
    }

    if (!EVP_DigestInit(hash, EVP_sm3())) {
        TRACE("%s\n", "EVP_DigestInit error");
        goto end;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */
    if (id_len >= (USHRT_MAX / 8)) {
        /* too large */
        TRACE("%s\n", "id_len too large");
        goto end;
    }

    entl = (unsigned short)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        TRACE("%s\n", "EVP_DigestUpdate error");
        goto end;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        TRACE("%s\n", "EVP_DigestUpdate error");
        goto end;
    }

    if (!EVP_DigestUpdate(hash, id, id_len)) {
        TRACE("%s\n", "EVP_DigestUpdate error");
        goto end;
    }

    /* 获取素数p，系数a，系数b */
    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        TRACE("%s\n", "EC_GROUP_get_curve error");
        goto end;
    }

    p_bytes = BN_num_bytes(p);
    buf = OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        TRACE("%s\n", "OPENSSL_zalloc error");
        goto end;
    }

    if (BN_bn2binpad(a, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(b, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group, 
                    EC_GROUP_get0_generator(group), xG, yG, ctx)
            || BN_bn2binpad(xG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group, 
                    EC_KEY_get0_public_key(key), xA, yA, ctx)
            || BN_bn2binpad(xA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EVP_DigestFinal(hash, out, NULL)) {
        TRACE("%s\n", "internal error");
        goto end;
    }
    rc = 1;
 end:
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}



/**
 * 密钥派生函数(实现参考OpenSSL1.1.1的ecdh_kdf.c)
 * 
 * @param out [OUT] 密钥
 * @param outlen [IN] 期望的密钥长度
 * @param Z [IN] 字节串
 * @param Zlen [IN] 字节串长度
 * @param md 摘要算法
 * @return int 1：成功, 0：失败
 */
int x963_kdf(unsigned char *out, size_t outlen,
                   const unsigned char *Z, size_t Zlen,
                   const EVP_MD *md)
{
    EVP_MD_CTX *mctx = NULL;
    int rv = 0;
    unsigned int i;
    size_t mdlen;
    unsigned char ctr[4];
    unsigned char mtmp[EVP_MAX_MD_SIZE];
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        return 0;
    }
    mdlen = EVP_MD_size(md);
    for (i = 1;;i++) {
        if (!EVP_DigestInit_ex(mctx, md, NULL))
            goto end;
        ctr[3] = i & 0xFF;
        ctr[2] = (i >> 8) & 0xFF;
        ctr[1] = (i >> 16) & 0xFF;
        ctr[0] = (i >> 24) & 0xFF;
        if (!EVP_DigestUpdate(mctx, Z, Zlen))
            goto end;
        if (!EVP_DigestUpdate(mctx, ctr, sizeof(ctr)))
            goto end;
        if (outlen >= mdlen) {
            if (!EVP_DigestFinal(mctx, out, NULL))
                goto end;
            outlen -= mdlen;
            if (outlen == 0)
                break;
            out += mdlen;
        } else {
            if (!EVP_DigestFinal(mctx, mtmp, NULL))
                goto end;
            memcpy(out, mtmp, outlen);
            break;
        }
    }
    rv = 1;
 end:
    EVP_MD_CTX_free(mctx);
    return rv;
}

int sm2_key_exchange(bool is_initiator, const unsigned char *this_id, size_t this_id_len,
    const unsigned char *other_id, size_t other_id_len,
    const unsigned char *this_prikey, const unsigned char *this_pubkey, 
    const unsigned char *this_tmp_prikey, const unsigned char *this_tmp_pubkey_x,
    const unsigned char *other_pubkey, const unsigned char *other_tmp_pubkey, 
    unsigned char *key, size_t keylen) {

    int ret = 0;
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *tmp_x = BN_new();
    BIGNUM *this_x = NULL;/* 己方临时公钥x分量 */
    BIGNUM *other_x = NULL;/* 对方临时公钥x分量 */
    BIGNUM *d = NULL;/* 己方固定私钥 */
    BIGNUM *r = NULL;/* 己方临时私钥 */
    BIGNUM *n = BN_new();/* 椭圆曲线的阶 */
    BIGNUM *t = BN_new();
    BIGNUM *this_x_ = BN_new();/* x_ = 2^w + (this_x & (2^w - 1)) */
    BIGNUM *other_x_ = BN_new();/* x_ = 2^w + (other_x & (2^w - 1)) */
    BIGNUM *R_x_bn = NULL;/* 对方临时公钥x分量 */
    BIGNUM *R_y_bn = NULL;/* 对方临时公钥y分量 */
    BIGNUM *P_x_bn = NULL;/* 对方固定公钥x分量 */
    BIGNUM *P_y_bn = NULL;/* 对方固定公钥y分量 */
    BIGNUM *two_power_w = BN_new();

    EC_POINT *P_point = NULL;/* 对方固定公钥坐标 */
    EC_POINT *R_point = NULL;/* 对方临时公钥坐标 */
    EC_POINT *V_point = NULL;

    unsigned char tmp_buf[128];

    const EC_GROUP *ec_group = NULL;

    unsigned char *pbuf = NULL;
    size_t pbuf_len = 0;
    size_t tmp_len = 0;

    EC_KEY *this_ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    EC_KEY *other_ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if((this_ec_key == NULL) || (other_ec_key == NULL)) {
        TRACE("%s\n", "EC_KEY_new_by_curve_name NID_sm2 error");
        goto end;
    }

    /**
    * SM2的曲线参数n为
    * FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123 
    * 是个定值, 所以这里用计算结果给w赋值, w = ceil(ceil(log2(n)) / 2) - 1 = 127
    */
    int w = 127;

    /* 从己方临时公钥中取出域元素x */
    this_x = BN_bin2bn(this_tmp_pubkey_x, 32, NULL);

    /* 从对方临时公钥中取出域元素x */
    other_x = BN_bin2bn(other_tmp_pubkey, 32, NULL);

    if ((this_x == NULL) || (other_x == NULL)) {
        TRACE("%s\n", "BN_bin2bn error");
        goto end;
    }

    /* 计算2^w */
    if (!BN_one(two_power_w)) {
        TRACE("%s\n", "BN_one error");
        goto end;
    }
    if (!BN_lshift(two_power_w, two_power_w, w)) {
        TRACE("%s\n", "BN_lshift error");
        goto end;
    }

    /**
     * 计算this_x_和other_x_
     * this_x_ = 2^w + (this_x & (2^w - 1))
     * other_x_ = 2^w + (other_x & (2^w - 1))
     * 注：x & (2^w - 1)用另一种方式x mod (2^w)计算, 结果一致
     */
    if (!BN_nnmod(this_x, this_x, two_power_w, bn_ctx)) {
        TRACE("%s\n", "BN_nnmod error");
        goto end;
    }
	if (!BN_add(this_x_, this_x, two_power_w)) {
        TRACE("%s\n", "BN_add error");
		goto end;
	}
    if (!BN_nnmod(other_x, other_x, two_power_w, bn_ctx)) {
        TRACE("%s\n", "BN_nnmod error");
        goto end;
    }
	if (!BN_add(other_x_, other_x, two_power_w)) {
        TRACE("%s\n", "BN_add error");
		goto end;
	}

    /* 计算t = (d + this_x_ · r) mod n */
    ec_group = EC_KEY_get0_group(this_ec_key);
    if (!EC_GROUP_get_order(ec_group, n, bn_ctx)) {
        TRACE("%s\n", "EC_GROUP_get_order error");
		goto end;
	}
    d = BN_bin2bn(this_prikey, 32, NULL);
    r = BN_bin2bn(this_tmp_prikey, 32, NULL);
    if ((d == NULL) || (r == NULL)) {
        TRACE("%s\n", "BN_bin2bn error");
        goto end;
    }
    if (!BN_mul(tmp_x, this_x_, r, bn_ctx)) {
        TRACE("%s\n", "BN_mul error");
        goto end;
    }
    if (!BN_mod_add(t, tmp_x, d, n, bn_ctx)) {
        TRACE("%s\n", "BN_mod_add error");
        goto end;
    }

    /* 计算V = P + [other_x_]R */
    R_x_bn = BN_bin2bn(other_tmp_pubkey, 32, NULL);
    R_y_bn = BN_bin2bn(other_tmp_pubkey + 32, 32, NULL);
    P_x_bn = BN_bin2bn(other_pubkey, 32, NULL);
    P_y_bn = BN_bin2bn(other_pubkey + 32, 32, NULL);
    if ((R_x_bn == NULL) || (R_y_bn == NULL)
        || (P_x_bn == NULL) || (P_y_bn == NULL)) {
        TRACE("%s\n", "BN_bin2bn error");
        goto end;
    }
    R_point = EC_POINT_new(ec_group);
    V_point = EC_POINT_new(ec_group);
    P_point = EC_POINT_new(ec_group);
    if ((R_point == NULL) || (V_point == NULL) || (P_point == NULL)) {
        TRACE("%s\n", "EC_POINT_new error");
        goto end;
    }
    if (!EC_POINT_set_affine_coordinates_GFp(ec_group, R_point, R_x_bn, R_y_bn, bn_ctx)) {
        TRACE("%s\n", "EC_POINT_set_affine_coordinates_GFp error");
        goto end;
    }

    if (!EC_POINT_mul(ec_group, V_point, NULL, R_point, other_x_, bn_ctx)) {
        TRACE("%s\n", "EC_POINT_mul error");
		goto end;
    }
    if (!EC_POINT_set_affine_coordinates_GFp(ec_group, P_point, P_x_bn, P_y_bn, bn_ctx)) {
        TRACE("%s\n", "EC_POINT_set_affine_coordinates_GFp error");
        goto end;
    }
    if (!EC_POINT_add(ec_group, V_point, V_point, P_point, bn_ctx)) {
        TRACE("%s\n", "EC_POINT_add error");
        goto end;
    }
    
    /* 计算V = [h · t]V, 余因子h = 1 */
    if (!EC_POINT_mul(ec_group, V_point, NULL, V_point, t, bn_ctx)) {
        TRACE("%s\n", "EC_POINT_mul error");
        goto end;
    }
    
    if (EC_POINT_is_at_infinity(ec_group, V_point)) {
        TRACE("%s\n", "EC_POINT_is_at_infinity error");
		goto end;
	}

    /* 将V转成字节数组, 注意输出结果首字节为一字节格式类型04 */
    if (!(pbuf_len = EC_POINT_point2buf(ec_group, V_point, POINT_CONVERSION_UNCOMPRESSED, &pbuf, bn_ctx))) {
        TRACE("%s\n", "EC_POINT_point2buf error");
		goto end;
	}

    /* 将己方公钥和对方公钥数组转成EC_KEY */
    tmp_buf[0] = 0x04;
    memcpy(tmp_buf + 1, this_pubkey, 64);
    if(!EC_KEY_oct2key(this_ec_key, tmp_buf, 65, NULL)) {
        TRACE("%s\n", "EC_KEY_oct2key error");
        goto end;
    }
    memcpy(tmp_buf + 1, other_pubkey, 64);
    if(!EC_KEY_oct2key(other_ec_key, tmp_buf, 65, NULL)) {
        TRACE("%s\n", "EC_KEY_oct2key error");
        goto end;
    }

    /* 计算 Xv || Yv || 发起方Z值 || 响应方Z值 */
    tmp_len = 0;
    memcpy(tmp_buf, pbuf + 1, pbuf_len - 1);
    tmp_len += pbuf_len - 1;
    if (is_initiator) {
        if(!sm2_compute_z_digest(tmp_buf + pbuf_len - 1, this_id, this_id_len, this_ec_key)
            || !sm2_compute_z_digest(tmp_buf + pbuf_len - 1 + 32, other_id, other_id_len, other_ec_key)) {
            TRACE("%s\n", "sm2_compute_z_digest error");
            goto end;
        }
    } else {
        if(!sm2_compute_z_digest(tmp_buf + pbuf_len - 1, other_id, other_id_len, other_ec_key)
            ||!sm2_compute_z_digest(tmp_buf + pbuf_len - 1 + 32, this_id, this_id_len, this_ec_key)) {
            TRACE("%s\n", "sm2_compute_z_digest error");
            goto end;
        }
    }
    tmp_len += 64;

    /* KDF */ 
    if (!x963_kdf(key, keylen, tmp_buf, tmp_len, EVP_sm3())) {
        TRACE("%s\n", "x963_kdf error");
        goto end;
    }
    ret = 1;
end:
    BN_CTX_free(bn_ctx);
    BN_free(tmp_x);
    BN_free(two_power_w);
    BN_free(this_x);
    BN_free(other_x);
    BN_free(this_x_);
    BN_free(other_x_);
    BN_free(t);
    BN_free(d);
    BN_free(r);
    BN_free(n);
    BN_free(R_x_bn);
    BN_free(R_y_bn);
    BN_free(P_x_bn);
    BN_free(P_y_bn);

    EC_POINT_free(R_point);
    EC_POINT_free(P_point);
    EC_POINT_free(V_point);

    EC_KEY_free(this_ec_key);
    EC_KEY_free(other_ec_key);
    OPENSSL_free(pbuf);
    return ret;
}