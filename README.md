# sm2-sign-verify
SM2 signing and verification implementation with OpenSSL1.1.1 in c 



**Usage**

```
gcc sm2_sign_verify.c -lcrypto
```



**References**

- [OpenSSL server public key from buffer to EVP_PKEY](https://stackoverflow.com/questions/58520237/openssl-server-public-key-from-buffer-to-evp-pkey)

- [Compute SM2 signature and verify it by invoking EVP interface in OpenSSL 1.1.1](https://blog.csdn.net/henter/article/details/105802665)
- [Openssl EVP to implement RSA and SM2 en/dec sign/verify](https://segmentfault.com/a/1190000023859098)
- [OpenSSL  SM2](https://www.openssl.org/docs/man1.1.1/man7/SM2.html)

- 《GMT 0009-2012 SM2密码算法使用规范 .pdf》
- 《GMT 0003.2-2012 SM2椭圆曲线公钥密码算法第2部分：数字签名算法.pdf》
- 《GMT 0003.5-2012 SM2椭圆曲线公钥密码算法第5部分：参数定义.pdf》
