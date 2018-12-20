import os
from rsa import bytesToInt, intToBytes

class DES():
    def __init__(self):
        # 置换选择 PC1
        self.name = 'des'
        self.initial_key_permutaion = [57, 49,  41, 33,  25,  17,  9,
								 1, 58,  50, 42,  34,  26, 18,
								10,  2,  59, 51,  43,  35, 27,
								19, 11,   3, 60,  52,  44, 36,
								63, 55,  47, 39,  31,  23, 15,
								 7, 62,  54, 46,  38,  30, 22,
								14,  6,  61, 53,  45,  37, 29,
								21, 13,   5, 28,  20,  12,  4]

        # 置换选择 PC2
        self.sub_key_permutation = [14, 17, 11, 24,  1,  5,
								 3, 28, 15,  6, 21, 10,
								23, 19, 12,  4, 26,  8,
								16,  7, 27, 20, 13,  2,
								41, 52, 31, 37, 47, 55,
								30, 40, 51, 45, 33, 48,
								44, 49, 39, 56, 34, 53,
								46, 42, 50, 36, 29, 32]

        # 初始置换 IP
        self.initial_message_permutation = [58, 50, 42, 34, 26, 18, 10, 2,
										60, 52, 44, 36, 28, 20, 12, 4,
										62, 54, 46, 38, 30, 22, 14, 6,
										64, 56, 48, 40, 32, 24, 16, 8,
										57, 49, 41, 33, 25, 17,  9, 1,
										59, 51, 43, 35, 27, 19, 11, 3,
										61, 53, 45, 37, 29, 21, 13, 5,
										63, 55, 47, 39, 31, 23, 15, 7]
        # 迭代次数与移位次数表
        self.key_shift_sizes = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

        # 扩展函数E
        self.message_expansion =  [32,  1,  2,  3,  4,  5,
							 4,  5,  6,  7,  8,  9,
							 8,  9, 10, 11, 12, 13,
							12, 13, 14, 15, 16, 17,
							16, 17, 18, 19, 20, 21,
							20, 21, 22, 23, 24, 25,
							24, 25, 26, 27, 28, 29,
							28, 29, 30, 31, 32,  1]
        # S盒
        self.S = [None for x in range(8)]
        self.S[0] = [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
			 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
			 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
			15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]

        self.S[1] = [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
                    3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
                    0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
                    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]

        self.S[2] = [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
                    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
                    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
                    1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]

        self.S[3] = [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
                    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
                    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
                    3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]

        self.S[4] = [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
                    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
                    4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
                    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]

        self.S[5] = [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
                    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
                    9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
                    4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]

        self.S[6] = [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
                    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
                    1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
                    6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]

        self.S[7] = [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
                    1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
                    7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
                    2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]

        # 置换 P
        self.right_sub_message_permutation = [16,  7, 20, 21,
									29, 12, 28, 17,
									 1, 15, 23, 26,
									 5, 18, 31, 10,
									 2,  8, 24, 14,
									32, 27,  3,  9,
									19, 13, 30,  6,
									22, 11,  4, 25]

        # 逆初始置换 P^(-1)
        self.final_message_permutation =  [40,  8, 48, 16, 56, 24, 64, 32,
									39,  7, 47, 15, 55, 23, 63, 31,
									38,  6, 46, 14, 54, 22, 62, 30,
									37,  5, 45, 13, 53, 21, 61, 29,
									36,  4, 44, 12, 52, 20, 60, 28,
									35,  3, 43, 11, 51, 19, 59, 27,
									34,  2, 42, 10, 50, 18, 58, 26,
									33,  1, 41,  9, 49, 17, 57, 25]

        # 生成密钥
        self.generate_key(os.urandom(8))
        


    def generate_key(self, key):
        '''
            key: 64位，8bytes
            生成16轮密钥
        '''
        # key: 从8个字节 变为 7个字节
        self.key = [] # bytes型，存放轮密钥
        key = self.substitution(key, self.initial_key_permutaion)
        key = bytesToInt(key)                 # 整形56位

        one28 = int('1111'*7, base=2)
        left28 = (key & (one28 << 28)) >> 28  # 左边28位
        right28 = key & one28                 # 右边28位
        for _rnd in range(16):
            lshift = self.key_shift_sizes[_rnd]              # 左移位数
            baseL = int('1'*lshift, base=2) << (28-lshift)   # 取left28和right28左边的数
            baseR = int('1'*(28-lshift), base=2)             # 取右边的数
            left28 = ((left28 & baseL) >> (28-lshift)) | ((left28 & baseR) << lshift)
            right28 = ((right28 & baseL) >> (28-lshift)) | ((right28 & baseR) << lshift)
            keyx = (left28 << 28) | right28
            self.key.append(self.substitution(intToBytes(keyx), self.sub_key_permutation))


    def encry_decry(self, mbs, is_e_d):
        '''
            mbs: bytes
            is_e_d: 判断时加密(0)还是解密(1)，主要区别初始置换和逆的初始置换
            return: bytes
        '''
        newMbs = bytes()
        # 每8个bytes进行加密
        for _i in range(len(mbs) // 8):
            bt = mbs[_i*8: (_i+1)*8]

            # 初始置换
            bt = self.substitution(bt, self.initial_message_permutation)
            
            # 16 轮加密
            for _r in range(16):
                _rnd = _r
                # 若是解密操作，则颠倒_rnd
                if is_e_d == 1:
                    _rnd = 15 -_r

                left4bytes = bt[:4]
                right4bytes = bt[4:]

                # Ri 扩展E
                bt_extended = self.substitution(right4bytes, self.message_expansion)
                # RiE xor Ki
                fxor = [(ord(bytes([a]))^ord(bytes([b]))) for (a,b) in zip(bt_extended, self.key[_rnd])]
                fxor = bytesToInt(bytes(fxor))
                # 代替选择S盒
                fxor_S = 0  # int
                for si in range(8):
                    ones = int('1'*6, base=2) << (42-si*6)
                    s_res = self.S_choose((fxor&ones)>>(42-si*6), self.S[si])
                    fxor_S = 16*fxor_S + s_res
                # 置换P
                fP = self.substitution(intToBytes(fxor_S), self.right_sub_message_permutation)
                # L(i-1) xor fP(置换P)
                right4bytes2 = [(ord(bytes([a]))^ord(bytes([b]))) for (a,b) in zip(fP, left4bytes)]
                left4bytes2 = right4bytes
                bt = left4bytes2 + bytes(right4bytes2)
            
            # 最后左右互换
            bt = bt[4:] + bt[:4]      
            # 最后逆初始置换    
            bt = self.substitution(bt, self.final_message_permutation)
            newMbs += bt
        return newMbs



    def encrypt(self, message):
        '''
            message: str(text) -> bytes -> encrypt_bytes 
            return: str(hex)
        '''
        # 转为 bytes
        mbs = message.encode()
        # 末尾补零，直到bytes数是8的倍数
        if len(mbs) % 8 != 0:
            mbs += b'\x00' * (8-len(mbs)%8)
        return self.encry_decry(mbs, 0).hex()
        

    def decrypt(self, message):
        '''
            message: str(hex) -> bytes -> decrypt_bytes -> str(text)
            return: str
        '''
        mbs = bytes().fromhex(message)
        return self.encry_decry(mbs, 1).decode()



    def substitution(self, X, subTable):
        '''
            将 X 按 置换表 subTable进行置换
            X:        bytes
            subTable: list(对应的位为X对应位的数)
            return: bytes, 和 list位数 等大的置换后的字节串
        '''
        X = bytesToInt(X)
        sumx = 0
        for i in subTable:
            sumx = 2*sumx + (1 if (1<<i-1) & X else 0)
        return sumx.to_bytes(8,'big')


    def S_choose(self, X, S):
        '''
            X: int(6位)
            S: S盒
            return: int
        '''
        row, col = 0, 0
        if X & (1<<5): 
            row = 1
        if X & 1:
            row = 2*row + 1
        for i in range(4):
            if X & (1<<(i+1)):
                col = 2*col+1
        return S[16*row+col]


if __name__ == '__main__':
    desdemo = DES()
    print(desdemo.decrypt(desdemo.encrypt('huangdr3 help message')))