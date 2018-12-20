# cryptography_demo
cryptography_v1.0

1. main.py: 主函数
  
2. rsa.py: RSA密码实现代码
  分组加密规则为：加密时取秘钥 n 的字节数减1进行加密，加密后扩展为n的字节数加1个字节；解密时取n.bytesLen+1个字节转换为int进行解密

3. des.py: DES实现代码

4. caesar.py: 凯撒密码实现代码

5. gui.py: 图形化界面的实现

6. utils.py: 常用函数
