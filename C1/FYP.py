# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'FYP.ui'
#
# Created by: PyQt4 UI code generator 4.12.1
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui
import sys
import socket
import select
import time
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from configparser import ConfigParser

parser = ConfigParser()
parser.read('servers.ini')

cfgServerIP = []
cfgServerNames = []
cfgServerUserNames = []
cfgServerAuth = []
cfgServerPort = []
cfgServerEnc = []
cfgServerKey = []

cfgNumServers = int(parser.get("general", "servers"))

for x in range(0,cfgNumServers):
    serverNun = "server" + str(x)
    cfgServerIP.append(parser.get(serverNun, "ip"))
    cfgServerPort.append(parser.get(serverNun, "port"))
    cfgServerNames.append(parser.get(serverNun, "name"))
    cfgServerUserNames.append(parser.get(serverNun, "username"))
    cfgServerAuth.append(parser.get(serverNun, "authcode"))
    cfgServerEnc.append(parser.get(serverNun, "mode"))
    cfgServerKey.append(parser.get(serverNun, "key"))

print(cfgServerIP)
print(cfgServerUserNames)
print(cfgServerAuth)

connected = False

# [name, sig]

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_MainWindow(QtGui.QMainWindow):
    global serverNun
    global cfgServerNames
    def __init__(self):
        QtGui.QMainWindow.__init__(self)
        self.setupUi(self)

    def setupUi(self, MainWindow):
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(1086, 769)
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.gridLayout_2 = QtGui.QGridLayout(self.centralwidget)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.tabWidget = QtGui.QTabWidget(self.centralwidget)
        self.tabWidget.setMinimumSize(QtCore.QSize(500, 0))
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.tab = QtGui.QWidget()
        self.tab.setObjectName(_fromUtf8("tab"))
        self.gridLayout = QtGui.QGridLayout(self.tab)
        self.gridLayout.setMargin(0)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.txtChat = QtGui.QTextEdit(self.tab)
        self.txtChat.setMaximumSize(QtCore.QSize(1000, 16777215))
        self.txtChat.setReadOnly(True)
        self.txtChat.setObjectName(_fromUtf8("txtChat"))
        self.verticalLayout.addWidget(self.txtChat)
        self.gridLayout.addLayout(self.verticalLayout, 1, 0, 1, 1)
        self.line_2 = QtGui.QFrame(self.tab)
        self.line_2.setFrameShape(QtGui.QFrame.HLine)
        self.line_2.setFrameShadow(QtGui.QFrame.Sunken)
        self.line_2.setObjectName(_fromUtf8("line_2"))
        self.gridLayout.addWidget(self.line_2, 2, 0, 1, 1)
        self.btnSendMsg = QtGui.QPushButton(self.tab)
        self.btnSendMsg.setMaximumSize(QtCore.QSize(1000, 16777215))
        self.btnSendMsg.setObjectName(_fromUtf8("btnSendMsg"))
        self.gridLayout.addWidget(self.btnSendMsg, 4, 0, 1, 1)
        self.txtNewMsg = QtGui.QTextEdit(self.tab)
        self.txtNewMsg.setMaximumSize(QtCore.QSize(1000, 50))
        self.txtNewMsg.setObjectName(_fromUtf8("txtNewMsg"))
        self.gridLayout.addWidget(self.txtNewMsg, 3, 0, 1, 1)
        self.tabWidget.addTab(self.tab, _fromUtf8(""))
        self.tab_2 = QtGui.QWidget()
        self.tab_2.setObjectName(_fromUtf8("tab_2"))
        self.tabWidget.addTab(self.tab_2, _fromUtf8(""))
        self.gridLayout_2.addWidget(self.tabWidget, 1, 3, 1, 1)
        self.lstOnlineUsers = QtGui.QListWidget(self.centralwidget)
        self.lstOnlineUsers.setMaximumSize(QtCore.QSize(200, 16777215))
        self.lstOnlineUsers.setObjectName(_fromUtf8("lstOnlineUsers"))
        self.gridLayout_2.addWidget(self.lstOnlineUsers, 1, 2, 1, 1)
        self.line = QtGui.QFrame(self.centralwidget)
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)
        self.line.setObjectName(_fromUtf8("line"))
        self.gridLayout_2.addWidget(self.line, 0, 3, 1, 1)
        self.line_3 = QtGui.QFrame(self.centralwidget)
        self.line_3.setFrameShape(QtGui.QFrame.HLine)
        self.line_3.setFrameShadow(QtGui.QFrame.Sunken)
        self.line_3.setObjectName(_fromUtf8("line_3"))
        self.gridLayout_2.addWidget(self.line_3, 0, 1, 1, 1)
        self.line_4 = QtGui.QFrame(self.centralwidget)
        self.line_4.setFrameShape(QtGui.QFrame.HLine)
        self.line_4.setFrameShadow(QtGui.QFrame.Sunken)
        self.line_4.setObjectName(_fromUtf8("line_4"))
        self.gridLayout_2.addWidget(self.line_4, 0, 2, 1, 1)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem, 1, 4, 1, 1)
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem1, 1, 0, 1, 1)

        self.lstServerList = QtGui.QListWidget(self.centralwidget)
        self.lstServerList.setMaximumSize(QtCore.QSize(200, 16777215))
        self.lstServerList.setViewMode(QtGui.QListView.ListMode)
        self.lstServerList.setObjectName(_fromUtf8("lstServerList"))


        for x in range(0,cfgNumServers):
            self.lstServerList.addItem(cfgServerNames[x])


        self.gridLayout_2.addWidget(self.lstServerList, 1, 1, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtGui.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1086, 25))
        self.menubar.setObjectName(_fromUtf8("menubar"))
        self.menuFile = QtGui.QMenu(self.menubar)
        self.menuFile.setObjectName(_fromUtf8("menuFile"))
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)
        self.actionSettings = QtGui.QAction(MainWindow)
        self.actionSettings.setObjectName(_fromUtf8("actionSettings"))
        self.actionAdd_Server = QtGui.QAction(MainWindow)
        self.actionAdd_Server.setObjectName(_fromUtf8("actionAdd_Server"))
        self.menuFile.addSeparator()
        self.menuFile.addAction(self.actionSettings)
        self.menuFile.addAction(self.actionAdd_Server)
        self.menubar.addAction(self.menuFile.menuAction())

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow", None))
        self.btnSendMsg.setText(_translate("MainWindow", "Submit", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "Tab 1", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "Tab 2", None))
        self.menuFile.setTitle(_translate("MainWindow", "File", None))
        self.actionSettings.setText(_translate("MainWindow", "Settings", None))
        self.actionAdd_Server.setText(_translate("MainWindow", "Add Server", None))
        self.btnSendMsg.clicked.connect(self.sendMsgPressed)
        self.lstServerList.clicked.connect(self.lstServerList_clicked)





    def sendMsgPressed(self):
        self.chat.sendMsg()


    def lstServerList_clicked(self,model_index):
        try:
            self.chat.close()
        except:
            pass

        global connected
        #Prevents Unwated wasted sockets
        if connected == True:
            connected = False
            self.chat.close()

        print("ID Pressed")
        print(self.lstServerList.currentRow())

        connected = True
        self.chat = chatThread(self.lstServerList.currentRow())
        self.connect(self.chat, QtCore.SIGNAL("update(QString)"), chatThread.start)
        self.chat.start()


class AESCipher(object):

    def __init__(self, key):
        self.bs = 16

        self.key = hashlib.sha256(key.encode()).digest()

    def encryptCBC(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decryptCBC(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def encryptCFB(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decryptCFB(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]




class chatThread(QtCore.QThread):
    global cfgServerIP
    global cfgServerUserNames
    global cfgServerAuth
    global cfgServerPort
    global cfgServerEnc
    def __init__(self, serverID):
        self.serverID = serverID
        self.encMode = cfgServerEnc[serverID]
        QtCore.QThread.__init__(self)
        self.userAuth = [cfgServerUserNames[serverID], cfgServerAuth[serverID]]
        global cfgServerKey
        password = cfgServerKey[serverID]
        self.AESEnc = AESCipher(password)

    def __del__(self):
        self.wait()

    def close(self):
        print("closeing Thread")
        self.msgSocket.send("TER".encode('utf-8'))
        self.terminate()

    def sendMsg(self):
        msg = str(ex.txtNewMsg.toPlainText() + "\n")
        print(msg)
        ex.txtChat.append("Me \n----------------\n" + msg)
        ex.txtNewMsg.setText("")
                        # user entered a message
        msg = "\n----------------\n" + msg
        if self.encMode == "CBC":
            msg = self.AESEnc.encryptCBC(msg)
            self.msgSocket.send(msg)
        elif self.encMode == "CFB":
            msg = self.AESEnc.encryptCFB(msg)
            self.msgSocket.send(msg)
        else:
            print("No Enc Mode")

    def run(self):

        host = cfgServerIP[self.serverID]
        port = int(cfgServerPort[self.serverID])

        self.msgSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.msgSocket.settimeout(2)


                # connect to remote host
        try :
            self.msgSocket.connect((host, port))
        except :
            print('Unable to connect')
            sys.exit()

        print('Connected to remote host. You can start sending messages')
        authMsg = "Auth!" + self.userAuth[0] + "!" + self.userAuth[1]
        self.msgSocket.send(authMsg.encode('utf-8'))

        #Has First Time User Update Been Done
        firstTimeCheck = False

        while True:
                    socket_list = [sys.stdin, self.msgSocket]

                        # Get the list sockets which are readable
                    ready_to_read,ready_to_write,in_error = select.select(socket_list , [], [])

                    for sock in ready_to_read:
                        if sock == self.msgSocket:
                            # incoming message from remote server, s
                            data = sock.recv(4096)
                            data = data.decode('utf-8')
                            if not data:
                                print('\nDisconnected from chat server')
                                sys.exit()
                            else:
                                if firstTimeCheck == False:
                                    firstTimeCheck = True
                                    #Onlune User Update Request
                                    ouur = "OUUR!"
                                    time.sleep(1)
                                    self.msgSocket.send(ouur.encode('utf-8'))
                                        #print data
                                if data[:4] == "OUU!":
                                    print("Test")
                                    data = str(data)
                                    onlineUsers = data.split("!")
                                    onlineUsersToTxt = []
                                    ex.lstOnlineUsers.clear()
                                    for u in range(0,len(onlineUsers)):
                                        if u % 2 == 0 and u != 0:
                                            print(str(onlineUsers[u]))
                                            onlineUsersToTxt.append(str(onlineUsers[u]))
                                            ex.lstOnlineUsers.addItem(onlineUsers[u])

                                    print(onlineUsersToTxt)
                                else:
                                    if self.encMode == "CBC":
                                        data = self.AESEnc.decryptCBC(data)
                                        ex.txtChat.append(data)
                                    elif self.encMode == "CFB":
                                        data = self.AESEnc.decryptCFB(data)
                                        ex.txtChat.append(data)
                                    else:
                                        print("No Enc Mode Set")





if __name__ == '__main__':
    app = QtGui.QApplication(sys.argv)
    ex = Ui_MainWindow()
    ex.show()






    sys.exit(app.exec_())
