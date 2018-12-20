import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QAction, QMessageBox, QTextEdit, QTextBrowser
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot
from PyQt5.Qt import QLineEdit
from rsa import RSA
from caesar import Caesar
from des import DES
from aes import AES

class App(QWidget):
    
    def __init__(self):
        super().__init__()
        self.title = 'Cryptographic experiments'

        # 窗口位置
        self.left = 100
        self.top = 100
        self.width = 1000
        self.height = 600

        # 文本框位置
        self.text_pos = [(self.left,self.top), (self.left+self.width//2, self.top)]
        self.text_size = (300,250)

        self.crypt = None

        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        # create textbox
        self.textbox = []
        self.textbox.append(QTextEdit(self))
        self.textbox.append(QTextBrowser(self))
        self.textbox.append(QTextBrowser(self))
        self.textbox[0].move(self.text_pos[0][0], self.text_pos[0][1])
        self.textbox[0].resize(self.text_size[0], self.text_size[1])
        self.textbox[1].move(self.text_pos[1][0], self.text_pos[1][1])
        self.textbox[1].resize(self.text_size[0], self.text_size[1])
        self.textbox[2].move(self.left, 380)
        self.textbox[2].resize(800, 200)

        # Create a button in the window
        self.button = []
        self.button.append(QPushButton('encrypt', self))
        self.button.append(QPushButton('decrypt', self))
        self.button.append(QPushButton('RSA',self))
        self.button.append(QPushButton('Caesar',self))
        self.button.append(QPushButton('DES', self))
        self.button.append(QPushButton('AES',self))

        self.button[0].move(self.left+self.width//4+100,self.top+5)
        self.button[1].move(self.left+self.width//4+100,self.top+45)
        self.button[2].move(20, 20)
        self.button[3].move(120, 20)
        self.button[4].move(220, 20)
        self.button[5].move(320, 20)


        # connect button to function on_click
        self.button[0].clicked.connect(self.on_click0)
        self.button[1].clicked.connect(self.on_click1)
        self.button[2].clicked.connect(self.on_click2)
        self.button[3].clicked.connect(self.on_click3)
        self.button[4].clicked.connect(self.on_click4)
        self.button[5].clicked.connect(self.on_click5)
        self.show()

    @pyqtSlot()
    def on_click0(self):
        text = self.textbox[0].toPlainText()
        if self.crypt is None:
            print('do not change a kind of encryption method')
            return 0
        enmessage = self.crypt.encrypt(text)
        self.textbox[1].setText(enmessage)
        print('encrypt end')
    
    @pyqtSlot()
    def on_click1(self):
        text = self.textbox[0].toPlainText()
        if self.crypt is None:
            print('do not change a kind of encryption method')
            return 0
        demessage = self.crypt.decrypt(text)
        self.textbox[1].setText(demessage)
        print('decrypt end')

    

    @pyqtSlot()
    def on_click2(self):
        self.crypt = RSA()
        helpMessage = 'use method: ' + self.crypt.name + '\nkey: '+ self.crypt.key
        self.textbox[2].setText(helpMessage)
    
    @pyqtSlot()
    def on_click3(self):
        self.crypt = Caesar(4)
        helpMessage = 'use method: ' + self.crypt.name + '\nkey: '+ self.crypt.key
        self.textbox[2].setText(helpMessage)

    @pyqtSlot()
    def on_click4(self):
        self.crypt = DES()
        helpMessage = 'use method: ' + self.crypt.name + '\nkey: \n'
        helpMessage += '\n'.join([str(s.hex()) for s in self.crypt.key])
        self.textbox[2].setText(helpMessage)

    @pyqtSlot()
    def on_click5(self):
        self.crypt = AES()
        helpMessage = 'use method: ' + self.crypt.name + '\nkey: ' + bytes(self.crypt.key).hex()
        self.textbox[2].setText(helpMessage)