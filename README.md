SM2 sign/verify/keychange/encrypt/decrypt implementation with OpenSSL1.1.1 in c 



**Compile**

```
$ gcc sm2_sign_verify.c test_sm2_sign_verify.c -lcrypto
$ gcc sm2_key_exchange.c test_sm2_key_exchange.c -lcrypto
$ gcc sm2_encrypt_decrypt.c test_sm2_encrypt_decrypt.c -lcrypto
```



**References**

- [OpenSSL server public key from buffer to EVP_PKEY](https://stackoverflow.com/questions/58520237/openssl-server-public-key-from-buffer-to-evp-pkey)
- [Compute SM2 signature and verify it by invoking EVP interface in OpenSSL 1.1.1](https://blog.csdn.net/henter/article/details/105802665)
- [Openssl EVP to implement RSA and SM2 en/dec sign/verify](https://segmentfault.com/a/1190000023859098)
- [GmSSL source code](https://github.com/guanzhi/GmSSL)
- [OpenSSL source code](https://github.com/openssl/openssl)
- 《GMT 0009-2012 SM2密码算法使用规范 .pdf》
- 《GMT 0003.2-2012 SM2椭圆曲线公钥密码算法第2部分：数字签名算法.pdf》
- 《GMT 0003.3-2012 SM2椭圆曲线公钥密码算法第3部分：密钥交换协议》
- 《GMT 0003.4-2012 SM2椭圆曲线公钥密码算法第4部分：公钥加密算法》
- 《GMT 0003.5-2012 SM2椭圆曲线公钥密码算法第5部分：参数定义.pdf》
