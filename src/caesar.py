
import random

class Caesar():
    def __init__(self, keynum = 4):
        self.key = ''
        for i in range(keynum):
            self.key += chr(random.randint(97, 97+25))        
        self.name = 'caesar'

    def set_key(self, key):
        self.key = key

    def encrypt(self, message):
        '''
        实现数据加密
            message: str(26個字母), 小写
            key: str(26個字母)
        return:
            res: str(26個字母)
        '''
        res = ''
        cur = 0
        roundCnt = len(self.key)
        # 对每一位进行加密并存储到res中
        for i, x in enumerate(message):
            res += chr((ord(x)-97 +ord(self.key[cur])-97) % 26 + 97)
            cur = (cur+1)%roundCnt
        return res 

    def decrypt(self, de):
        '''
        实现数据解密
            de: str(26個字母)
            return: str(26個字母)
        '''
        res = ''
        cur = 0
        roundCnt = len(self.key)
        # 对每一位进行解密并存储到res中
        for i, x in enumerate(de):
            res += chr((ord(x) - ord(self.key[cur])) % 26 + 97)
            cur = (cur+1)%roundCnt
        return res 

if __name__ == '__main__':
    ca = Caesar()
    message = 'fasfsfasd'
    de = ca.encrypt(message)
    print(de)
    print(ca.decrypt(de))
    

