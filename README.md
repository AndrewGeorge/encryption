如基本的单向加密算法： 
BASE64 严格地说，属于编码格式，而非加密算法
MD5(Message Digest algorithm 5，信息摘要算法)
SHA(Secure Hash Algorithm，安全散列算法)
HMAC(Hash Message Authentication Code，散列消息鉴别码)

复杂的对称加密（DES、PBE）、非对称加密算法： 
DES(Data Encryption Standard，数据加密算法)
PBE(Password-based encryption，基于密码验证)
RSA(算法的名字以发明者的名字命名：Ron Rivest, AdiShamir 和Leonard Adleman)
DH(Diffie-Hellman算法，密钥一致协议)
DSA(Digital Signature Algorithm，数字签名)
ECC(Elliptic Curves Cryptography，椭圆曲线密码编码学)

里面包含了  MD5、SHA以及HMAC，DH加密，一些我自己学习的一些源码
另外附上牛人的博客链接：
http://snowolf.iteye.com/blog/379860
对加密这块想了解更多的朋友可以查看这位大牛的博客
下面是我自己学习，写的测试结果

甲方公钥:
MIIBpzCCARsGCSqGSIb3DQEDATCCAQwCgYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/gLZR
JmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfGG/g7
V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCgYEA9+GghdabPd7LvKtc
NrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotU
fI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7P
SSoCAgIAA4GFAAKBgQCEw7v/kXI98XocsWC116wdmuVy0yMlQbRHwhx69hinEl0mATc6H6bEj/Ga
N5vczYl2A1f2pC15nMWKjR6PrzVyQvLnpV3/MsljSPDd3qYBZEKn9rkBDLtSCtCLHXIfMdll5Rwu
tlj/KPgLiyToz5YSIqxSl57gniDRHVR9CVqTlA==

甲方私钥:
MIIBZwIBADCCARsGCSqGSIb3DQEDATCCAQwCgYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/
gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfG
G/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCgYEA9+GghdabPd7L
vKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwW
eotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFM
O/7PSSoCAgIABEMCQQCtNmPyvnoyLKdtusJ4wVmN2oY1Z06dYS/ZreMC2c0Qy/TxO4+UJOJO8aiu
cQfzYa8hx/KL0mhhMpdK0Jwy59n2

乙方公钥:
MIIBpjCCARsGCSqGSIb3DQEDATCCAQwCgYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/gLZR
JmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfGG/g7
V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCgYEA9+GghdabPd7LvKtc
NrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotU
fI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7P
SSoCAgIAA4GEAAKBgDiTMAOO81JpzLrK7SlaTC+RdsH0kZsYFO1TuUNHfFpFPgrQKv32BNnFZiRX
3EsnOiZQ5Gpa+QW6rGH2CzGCVijMUd3au30lgD7TCiDvM0dPd6h+i87RUBBIhDNf9Qkh/qMbrVKS
npM4CdmWtpTc3S0jGQN1+rGftnGHW6zBeUo5

乙方私钥:
MIIBZwIBADCCARsGCSqGSIb3DQEDATCCAQwCgYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/
gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfG
G/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCgYEA9+GghdabPd7L
vKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwW
eotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFM
O/7PSSoCAgIABEMCQQCPHUI8EJKecF+FAVd8gcueS9H+wIQIe72/vq5hW4d6LixHwYuh553t1oAt
6ZG86vkAgjX3x42DDD+jWIROgDTW

原文: jsahjdhj
密文: O+��ТO��eU�3%�
解密后: jsahjdhj
原文: djkljadkljkljlk 
密文: �y���*_�ʀ���eU�3%�
解密后: djkljadkljkljlk 
原文:
简单加密
BASE64加密后:
566A5Y2V5Yqg5a+G

BASE64解密后:
简单加密
Mac密钥:
Y8u/rI6/R1N883Uk/JdubR2ZUsx9ixhyeVpS2sSkwWokQ/OsFeEPByZiTPJUeXoiLVJoQy7CSGYE
wR3W2zVadA==

MD5:
-550b4d90349ad4629462113e7934de56
SHA:
91k9vo7p400cjkgfhjh0ia9qthsjagfn
HMAC:
2287d192387e95694bdbba2fa941009a
原文:	DES
密钥:	pBolGtmG6fg=

加密后:	mOGz2J+4D/Q=

解密后:	DES
