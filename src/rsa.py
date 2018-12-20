import random
import os
from utils import bytesToInt, intToBytes

class RSA():
    def __init__(self):
        self.e, self.d, self.n = self.generate_secret_key()
        nb = self.n.bit_length()
        self.nBytes = nb // 8 + (0 if nb % 8 == 0 else 1)   #self.n的字节数
        self.encrypt_packet_length = self.nBytes - 1  # 加密分组长度，n的字节数-1
        self.decrypt_packet_length = self.nBytes + 1  # 解密分组长度

        self.name = 'RSA'
        self.key = 'e: ' + str(self.e) + '\nd: ' + str(self.d) + '\nn: ' + str(self.n)

    def set_secret_key(self, ex,dx,nx):
        self.e = ex
        self.d = dx
        self.n = nx

    def is_prime(self, n, r=10):
        '''判断是否是prime'''
        # small number
        if n < 10:
            return n in {2,3,5,7}

        # if even
        if n & 1 == 0:
            return False

        # n-1 = 2^k * m
        m = n-1
        k = 0
        while (m & 1) == 0:
            k += 1
            m >>= 1
        
        # test r count
        for _ in range(r):
            # choose an integer a in range[2, n-2] randomly
            a = random.randint(2, n-2)
            b = pow(a,m,n)

            # this test pass, continue next test
            if b == 1 or b == n-1:
                continue

            for _ in range(k-1):
                b = pow(b,2,n)
                # b == 1时，b^2 mod n 永远为1
                if b == 1:
                    return False
                if b == n-1:  # this test pass
                    break
            else:
                return False

        return True

    def generate_prime(self, nbits=512):
        '''
            随机生成一个素数
        input:
            nbits: int, 素数的二进制位数
        '''
        nbytes = nbits // 8 + (0 if nbits % 8 == 0 else 1)
        while 1:
            x = bytesToInt(os.urandom(nbytes))
            if self.is_prime(x):
                return x
        

    def extended_gcd(self, a, b):
        '''
            扩展欧几里得算法 r = gcd(a, b) = ma + nb
        return:
            1: gcd(a,b)
            2: a^(-1) mod b, a的逆
            3: b^(-1) mod a
        '''
        oa, ob = a, b
        om, on = 1, 0  # o: old
        m, n = 0, 1
        while b!=0:
            q = a//b
            (a, b) = (b, a%b)
            (om, m) = (m, om-q*m)
            (on, n) = (n, on-q*n)
        return a, om%ob, on%oa


    def calc_inverse(self, e, n):
        gcd, inv, _ = self.extended_gcd(e, n)
        if gcd != 1:
            return False
        return inv

    def RSA_EncryptDecrypt(self, X, ed, n):
        return pow(X,ed,n)

    def generate_secret_key(self):
        while 1:
            p = self.generate_prime()
            q = self.generate_prime()
            if p == q:
                continue
            e = self.generate_prime()
            n = p*q
            phi_n = (p-1)*(q-1)
            if e >= phi_n:
                continue
            d = self.calc_inverse(e, phi_n)
            if d != False:
                break
        return e, d, n


    def encrypt(self, X):
        '''X: str(text), return: str(bytes(1024*n))'''
        res = ''  #返回的字符     
        _x = X.encode()
        encry_times = len(_x)//self.encrypt_packet_length  #加密次数

        for i in range(encry_times):
            # 将_x转为int
            _xi = bytesToInt(_x[i*self.encrypt_packet_length:(i+1)*self.encrypt_packet_length])   
            # 加密
            _yi = pow(_xi, self.e, self.n)
            # 将加密后int转为字符串
            res += _yi.to_bytes(self.decrypt_packet_length, 'big').hex()
        
        # 若还有剩余的为加密的数据则进行最后的加密
        if len(_x)%self.encrypt_packet_length != 0: 
            _xi = bytesToInt(_x[encry_times * self.encrypt_packet_length:]) 
            _yi = pow(_xi, self.e, self.n)
            res += _yi.to_bytes(self.decrypt_packet_length, 'big').hex()

        return res


    def decrypt(self, X):
        '''X: str(hex), return: str(text)'''
        res = b''        
        decry_times = len(X)//2//self.decrypt_packet_length   #加密次数即分组数
        for i in range(decry_times):
            _xi = int(X[i*self.decrypt_packet_length*2: (i+1)*self.decrypt_packet_length*2], base=16)  # 将16进制的字符串转化为int型
            _xi = pow(_xi,self.d, self.n)
            res += intToBytes(_xi)   
        return res.decode()

