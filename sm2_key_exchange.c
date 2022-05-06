#include <openssl/bn.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <string.h>

/**
 * 计算Z值(实现参考OpenSSL1.1.1的sm2_sign.c)
 * 公式: Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
 * 
 * @param out [OUT] 32字节Z值
 * @param id [IN] ID
 * @param id_len [IN] ID长度
 * @param key [IN] 设置过公钥的EC_KEY
 * @return int 1:成功, 0:失败
 */
int sm2_compute_z_digest(unsigned char *out, const unsigned char *id,
    const size_t id_len, EC_KEY *key)
{
    int rc = 0;
    const char *log_tag = "sm2_compute_z_digest";
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
        printf("%s:EVP_MD_CTX_new or BN_CTX_new error\n", log_tag);
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
        printf("%s:BN_CTX_get error\n", log_tag);
        goto end;
    }

    if (!EVP_DigestInit(hash, EVP_sm3())) {
        printf("%s:EVP_DigestInit error\n", log_tag);
        goto end;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */
    if (id_len >= (USHRT_MAX / 8)) {
        /* too large */
        printf("%s:id_len too large\n", log_tag);
        goto end;
    }

    entl = (unsigned short)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        printf("%s:EVP_DigestUpdate error\n", log_tag);
        goto end;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        printf("%s:EVP_DigestUpdate error\n", log_tag);
        goto end;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        printf("%s:EVP_DigestUpdate error\n", log_tag);
        goto end;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {//获取素数p，系数a，系数b
        printf("%s:EC_GROUP_get_curve error\n", log_tag);
        goto end;
    }

    p_bytes = BN_num_bytes(p);
    buf = OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        printf("%s:OPENSSL_zalloc error\n", log_tag);
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
        printf("%s:internal error\n", log_tag);
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
 * @return int 1:成功, 0:失败
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
            // OPENSSL_cleanse(mtmp, mdlen);
            break;
        }
    }
    rv = 1;
 end:
    EVP_MD_CTX_free(mctx);
    return rv;
}

/**
 * 密钥交换, 输出共享密钥(实现参考GmSSL的sm2_exch.c)
 * 
 * @param is_initiator [IN] 1:发起方 0:响应方
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
int sm2_key_exchange(int is_initiator, const unsigned char *this_id, size_t this_id_len,
    const unsigned char *other_id, size_t other_id_len,
    const unsigned char *this_prikey, const unsigned char *this_pubkey, 
    const unsigned char *this_tmp_prikey, const unsigned char *this_tmp_pubkey_x,
    const unsigned char *other_pubkey, const unsigned char *other_tmp_pubkey, 
    unsigned char *key, size_t keylen) {

    int ret = 0;
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *tmp_x = BN_new();
    BIGNUM *this_x = NULL;//己方临时公钥x分量
    BIGNUM *other_x = NULL;//对方临时公钥x分量
    BIGNUM *d = NULL;//己方固定私钥
    BIGNUM *r = NULL;//己方临时私钥
    BIGNUM *n = BN_new();//椭圆曲线的阶
    BIGNUM *t = BN_new();
    BIGNUM *this_x_ = BN_new();//x_ = 2^w + (this_x & (2^w - 1))
    BIGNUM *other_x_ = BN_new();//x_ = 2^w + (other_x & (2^w - 1))
    BIGNUM *R_x_bn = NULL;//对方临时公钥x分量
    BIGNUM *R_y_bn = NULL;//对方临时公钥y分量
    BIGNUM *P_x_bn = NULL;//对方固定公钥x分量
    BIGNUM *P_y_bn = NULL;//对方固定公钥y分量
    BIGNUM *two_power_w = BN_new();

    EC_POINT *P_point = NULL;//对方固定公钥坐标
    EC_POINT *R_point = NULL;//对方临时公钥坐标
    EC_POINT *V_point = NULL;

    unsigned char tmp_buf[128];

    const EC_GROUP *ec_group = NULL;

    unsigned char *pbuf = NULL;
    size_t pbuf_len = 0;
    size_t tmp_len = 0;
    char *log_tag = "sm2_key_exchange";

    EC_KEY *this_ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    EC_KEY *other_ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if((this_ec_key == NULL) || (other_ec_key == NULL)) {
        printf("%s:EC_KEY_new_by_curve_name NID_sm2 error\n", log_tag);
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
        printf("%s:BN_bin2bn error\n", log_tag);
        goto end;
    }

    /* 计算2^w */
    if (!BN_one(two_power_w)) {
        printf("%s:BN_one error\n", log_tag);
        goto end;
    }
    if (!BN_lshift(two_power_w, two_power_w, w)) {
        printf("%s:BN_lshift error\n", log_tag);
        goto end;
    }

    /**
     * 计算this_x_和other_x_
     * this_x_ = 2^w + (this_x & (2^w - 1))
     * other_x_ = 2^w + (other_x & (2^w - 1))
     * 注：x & (2^w - 1)用另一种方式x mod (2^w)计算, 结果一致
     */
    if (!BN_nnmod(this_x, this_x, two_power_w, bn_ctx)) {
        printf("%s:BN_lshift error\n", log_tag);
        goto end;
    }
	if (!BN_add(this_x_, this_x, two_power_w)) {
		printf("%s:BN_add error\n", log_tag);
		goto end;
	}
    if (!BN_nnmod(other_x, other_x, two_power_w, bn_ctx)) {
        printf("%s:BN_lshift error\n", log_tag);
        goto end;
    }
	if (!BN_add(other_x_, other_x, two_power_w)) {
		printf("%s:BN_add error\n", log_tag);
		goto end;
	}

    /* 计算t = (d + this_x_ · r) mod n */
    ec_group = EC_KEY_get0_group(this_ec_key);
    if (!EC_GROUP_get_order(ec_group, n, bn_ctx)) {
		printf("%s:EC_GROUP_get_order error\n", log_tag);
		goto end;
	}
    d = BN_bin2bn(this_prikey, 32, NULL);
    r = BN_bin2bn(this_tmp_prikey, 32, NULL);
    if ((d == NULL) || (r == NULL)) {
        printf("%s:BN_bin2bn error\n", log_tag);
        goto end;
    }
    if (!BN_mul(tmp_x, this_x_, r, bn_ctx)) {
        printf("%s:BN_mul error\n", log_tag);
        goto end;
    }
    if (!BN_mod_add(t, tmp_x, d, n, bn_ctx)) {
        printf("%s:BN_mod_add error\n", log_tag);
        goto end;
    }

    /* 计算V = P + [other_x_]R */
    R_x_bn = BN_bin2bn(other_tmp_pubkey, 32, NULL);
    R_y_bn = BN_bin2bn(other_tmp_pubkey + 32, 32, NULL);
    P_x_bn = BN_bin2bn(other_pubkey, 32, NULL);
    P_y_bn = BN_bin2bn(other_pubkey + 32, 32, NULL);
    if ((R_x_bn == NULL) || (R_y_bn == NULL)
        || (P_x_bn == NULL) || (P_y_bn == NULL)) {
        printf("%s:BN_bin2bn error\n", log_tag);
        goto end;
    }
    R_point = EC_POINT_new(ec_group);
    V_point = EC_POINT_new(ec_group);
    P_point = EC_POINT_new(ec_group);
    if ((R_point == NULL) || (V_point == NULL) || (P_point == NULL)) {
        printf("%s:EC_POINT_new error\n", log_tag);
        goto end;
    }
    if (!EC_POINT_set_affine_coordinates_GFp(ec_group, R_point, R_x_bn, R_y_bn, bn_ctx)) {
        printf("%s:EC_POINT_set_affine_coordinates_GFp error\n", log_tag);
        goto end;
    }

    if (!EC_POINT_mul(ec_group, V_point, NULL, R_point, other_x_, bn_ctx)) {
		printf("%s:EC_POINT_mul error\n", log_tag);
		goto end;
    }
    if (!EC_POINT_set_affine_coordinates_GFp(ec_group, P_point, P_x_bn, P_y_bn, bn_ctx)) {
        printf("%s:EC_POINT_set_affine_coordinates_GFp error\n", log_tag);
        goto end;
    }
    if (!EC_POINT_add(ec_group, V_point, V_point, P_point, bn_ctx)) {
        printf("%s:EC_POINT_add error\n", log_tag);
        goto end;
    }
    
    /* 计算V = [h · t]V, 余因子h = 1 */
    if (!EC_POINT_mul(ec_group, V_point, NULL, V_point, t, bn_ctx)) {
        printf("%s:EC_POINT_mul error\n", log_tag);
        goto end;
    }
    
    if (EC_POINT_is_at_infinity(ec_group, V_point)) {
		printf("%s:EC_POINT_is_at_infinity error\n", log_tag);
		goto end;
	}

    /* 将V转成字节数组, 注意输出结果首字节为一字节格式类型04 */
    if (!(pbuf_len = EC_POINT_point2buf(ec_group, V_point, POINT_CONVERSION_UNCOMPRESSED, &pbuf, bn_ctx))) {
		printf("%s:EC_POINT_point2buf error\n", log_tag);
		goto end;
	}

    /* 将己方公钥和对方公钥数组转成EC_KEY */
    tmp_buf[0] = 0x04;
    memcpy(tmp_buf + 1, this_pubkey, 64);
    if(EC_KEY_oct2key(this_ec_key, tmp_buf, 65, NULL) != 1) {
        printf("%s:EC_KEY_oct2key error\n", log_tag);
        goto end;
    }
    memcpy(tmp_buf + 1, other_pubkey, 64);
    if(EC_KEY_oct2key(other_ec_key, tmp_buf, 65, NULL) != 1) {
        printf("%s:EC_KEY_oct2key error\n", log_tag);
        goto end;
    }

    /* 计算 Xv || Yv || 发起方Z值 || 响应方Z值 */
    tmp_len = 0;
    memcpy(tmp_buf, pbuf + 1, pbuf_len - 1);
    tmp_len += pbuf_len - 1;
    if (is_initiator) {
        if(!sm2_compute_z_digest(tmp_buf + pbuf_len - 1, this_id, this_id_len, this_ec_key)
            || !sm2_compute_z_digest(tmp_buf + pbuf_len - 1 + 32, other_id, other_id_len, other_ec_key)) {
            printf("%s:sm2_compute_z_digest error\n", log_tag);
            goto end;
        }
    } else {
        if(!sm2_compute_z_digest(tmp_buf + pbuf_len - 1, other_id, other_id_len, other_ec_key)
            ||!sm2_compute_z_digest(tmp_buf + pbuf_len - 1 + 32, this_id, this_id_len, this_ec_key)) {
            printf("%s:sm2_compute_z_digest error\n", log_tag);
            goto end;
        }
    }
    tmp_len += 64;

    /* KDF */ 
    if (!x963_kdf(key, keylen, tmp_buf, tmp_len, EVP_sm3())) {
        printf("%s:x963_kdf error\n", log_tag);
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


/**
 * 使用《GMT 0003.5-2012 SM2椭圆曲线公钥密码算法第5部分：参数定义》附录B的密钥交换示例数据来验证
 * 
 * 该例子中用户A作为发起方, 用户B作为响应方
 * 
 * 用户A ID: 31323334 35363738 31323334 35363738
 * 用户A私钥: 81EB26E9 41BB5AF1 6DF11649 5F906952 72AE2CD6 3D6C4AE1 678418BE 48230029
 * 用户A公钥x坐标: 160E1289 7DF4EDB6 1DD812FE B96748FB D3CCF4FF E26AA6F6 DB9540AF 49C94232
 * 用户A公钥y坐标: 4A7DAD08 BB9A4595 31694BEB 20AA489D 6649975E 1BFCF8C4 741B78B4 B223007F
 * 用户A临时私钥: D4DE1547 4DB74D06 491C440D 305E0124 00990F3E 390C7E87 153C12DB 2EA60BB3
 * 用户A临时公钥x坐标: 64CED1BD BC99D590 049B434D 0FD73428 CF608A5D B8FE5CE0 7F150269 40BAE40E
 * 用户A临时公钥y坐标: 376629C7 AB21E7DB 26092249 9DDB118F 07CE8EAA E3E7720A FEF6A5CC 062070C0
 * 
 * 用户B ID: 31323334 35363738 31323334 35363738
 * 用户B私钥: 78512991 7D45A9EA 5437A593 56B82338 EAADDA6C EB199088 F14AE10D EFA229B5
 * 用户B公钥x坐标: 6AE848C5 7C53C7B1 B5FA99EB 2286AF07 8BA64C64 591B8B56 6F7357D5 76F16DFB
 * 用户B公钥y坐标: EE489D77 1621A27B 36C5C799 2062E9CD 09A92643 86F3FBEA 54DFF693 05621C4D
 * 用户B临时私钥: 7E071248 14B30948 9125EAED 10111316 4EBF0F34 58C5BD88 335C1F9D 596243D6
 * 用户B临时公钥x坐标: ACC27688 A6F7B706 098BC91F F3AD1BFF 7DC2802C DB14CCCC DB0A9047 1F9BD707
 * 用户B临时公钥y坐标: 2FEDAC04 94B2FFC4 D6853876 C79B8F30 1C6573AD 0AA50F39 FC87181E 1A1B46FE
 * 
 * 共享密钥: 6C893473 54DE2484 C60B4AB1 FDE4C6E5
 * 
 * 注: 下面定义的数据将用户A作为己方
 */

/* 己方ID */
static const unsigned char s_this_id[] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

/* 对方ID */
static const unsigned char s_other_id[] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

/* 己方固定私钥 */
static const unsigned char s_this_prikey[] = {
    0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1, 
    0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52, 
    0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1, 
    0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29
};

/* 己方固定公钥 */
static const unsigned char s_this_pubkey[] = {
    0x16, 0x0E, 0x12, 0x89, 0x7D, 0xF4, 0xED, 0xB6, 
    0x1D, 0xD8, 0x12, 0xFE, 0xB9, 0x67, 0x48, 0xFB, 
    0xD3, 0xCC, 0xF4, 0xFF, 0xE2, 0x6A, 0xA6, 0xF6, 
    0xDB, 0x95, 0x40, 0xAF, 0x49, 0xC9, 0x42, 0x32,
    
    0x4A, 0x7D, 0xAD, 0x08, 0xBB, 0x9A, 0x45, 0x95, 
    0x31, 0x69, 0x4B, 0xEB, 0x20, 0xAA, 0x48, 0x9D, 
    0x66, 0x49, 0x97, 0x5E, 0x1B, 0xFC, 0xF8, 0xC4,
    0x74, 0x1B, 0x78, 0xB4, 0xB2, 0x23, 0x00, 0x7F
};

/* 己方临时私钥 */
static const unsigned char s_this_tmp_prikey[] = {
    0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06, 
    0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24, 
    0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87, 
    0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3
};

/* 己方临时公钥x坐标 */
static const unsigned char s_this_tmp_pubkey_x[] = {
    0x64, 0xCE, 0xD1, 0xBD, 0xBC, 0x99, 0xD5, 0x90,
    0x04, 0x9B, 0x43, 0x4D, 0x0F, 0xD7, 0x34, 0x28,
    0xCF, 0x60, 0x8A, 0x5D, 0xB8, 0xFE, 0x5C, 0xE0,
    0x7F, 0x15, 0x02, 0x69, 0x40, 0xBA, 0xE4, 0x0E
};

/* 对方固定公钥 */
static const unsigned char s_other_pubkey[] = {
    0x6A, 0xE8, 0x48, 0xC5, 0x7C, 0x53, 0xC7, 0xB1, 
    0xB5, 0xFA, 0x99, 0xEB, 0x22, 0x86, 0xAF, 0x07, 
    0x8B, 0xA6, 0x4C, 0x64, 0x59, 0x1B, 0x8B, 0x56, 
    0x6F, 0x73, 0x57, 0xD5, 0x76, 0xF1, 0x6D, 0xFB, 

    0xEE, 0x48, 0x9D, 0x77, 0x16, 0x21, 0xA2, 0x7B, 
    0x36, 0xC5, 0xC7, 0x99, 0x20, 0x62, 0xE9, 0xCD, 
    0x09, 0xA9, 0x26, 0x43, 0x86, 0xF3, 0xFB, 0xEA, 
    0x54, 0xDF, 0xF6, 0x93, 0x05, 0x62, 0x1C, 0x4D
};

/* 对方临时公钥 */
static const unsigned char s_other_tmp_pubkey[] = {
    0xAC, 0xC2, 0x76, 0x88, 0xA6, 0xF7, 0xB7, 0x06,
    0x09, 0x8B, 0xC9, 0x1F, 0xF3, 0xAD, 0x1B, 0xFF, 
    0x7D, 0xC2, 0x80, 0x2C, 0xDB, 0x14, 0xCC, 0xCC, 
    0xDB, 0x0A, 0x90, 0x47, 0x1F, 0x9B, 0xD7, 0x07, 
    
    0x2F, 0xED, 0xAC, 0x04, 0x94, 0xB2, 0xFF, 0xC4, 
    0xD6, 0x85, 0x38, 0x76, 0xC7, 0x9B, 0x8F, 0x30, 
    0x1C, 0x65, 0x73, 0xAD, 0x0A, 0xA5, 0x0F, 0x39, 
    0xFC, 0x87, 0x18, 0x1E, 0x1A, 0x1B, 0x46, 0xFE
};

/* 期望的共享密钥值 */
static const unsigned char s_expected_key[] = {
    0x6C, 0x89, 0x34, 0x73, 0x54, 0xDE, 0x24, 0x84, 
    0xC6, 0x0B, 0x4A, 0xB1, 0xFD, 0xE4, 0xC6, 0xE5
};

int main(int argc, char **argv) 
{
    unsigned char key[16] = {0};
    
    /* 这里模拟发起方(用户A)进行密钥计算 */
    if (!sm2_key_exchange(1, s_this_id, sizeof(s_this_id), 
        s_other_id, sizeof(s_other_id),
        s_this_prikey, s_this_pubkey, 
        s_this_tmp_prikey, s_this_tmp_pubkey_x,
        s_other_pubkey, s_other_tmp_pubkey, 
        key, 16)) {
            printf("sm2_key_exchange error\n");
            return 0;
        }
    
    if (memcmp(s_expected_key, key, 16) == 0) {
        printf("sm2_key_exchange test passed\n");
    } else {
        printf("sm2_key_exchange test failed\n");
    }

    return 0;
}