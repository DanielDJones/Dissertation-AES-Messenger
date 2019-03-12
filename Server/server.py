# chat_server.py
print("""
What Enc Mode Do You Want To Use
1) CBC
2) CFB
""")
enctype = input()
if enctype == "2":
    print("CFB Selected")
    enctype = "CFB"
else:
    print("CBC Selected")
    enctype = "CBC"
print("Enter Enc Key")
key = input()


import sys
import socket
import select
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

HOST = ''
SOCKET_LIST = []
RECV_BUFFER = 4096
PORT = 9009
onlineUsers = {}
userInFile = {}

def readUsers():
    with open('users.txt', 'r') as userFile:
        lineNum = 0
        for line in userFile:
            lineNum += 1
            if lineNum % 2 == 0:
                print('Auth:', end='')
                userInFile[userName] = line
            else:
                print('Name:', end='')
                userName = line
            print(lineNum)
            print(line, end='')

def checkAuth(userName, userPass):
    userPass = hashlib.sha512(userPass.encode('utf-8')).hexdigest()
    with open('users.txt', 'a') as userFile:
        if (userName + "\n") in userInFile.keys():
            print("User in File!")
            if (userPass + '\n') == userInFile[userName + '\n']:
                print("Passwords match")
                passval = 1
            else:
                print("Incorrect Password")
                passval = 0
        else:
            print("Adding To Passlist")
            userFile.write(userName)
            passToStore = "\n" + userPass + "\n"
            userFile.write(passToStore)
            print('Appended!')
            userInFile[userName] = userPass
            passval = 1
        return passval

readUsers()

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

AESEnc = AESCipher(key)

def chat_server():
    global onlineUsers
    global userInFile
    global enctype
    user = ""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    # add server socket object to the list of readable connections
    SOCKET_LIST.append(server_socket)

    print("Chat server started on port " + str(PORT))

    while 1:

        # get the list sockets which are ready to be read through select
        # 4th arg, time_out  = 0 : poll and never block
        ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)

        for sock in ready_to_read:
            # a new connection request recieved
            if sock == server_socket:
                sockfd, addr = server_socket.accept()
                SOCKET_LIST.append(sockfd)

                print("Updateing Online Users")
                print(str(onlineUsers))
                toSend = "OUU!" + str(onlineUsers) + "END"
                broadcast(server_socket, sock, toSend)


            # a message from a client, not a new connection
            else:
                # process data recieved from client,
                try:
                    # receiving data from the socket.
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        # there is something in the socket
                        data = data.decode('utf-8')
                        print(data)
                        if data[:5] == "Auth!":
                            print("Auth...")
                            print("test")
                            newUser = data.split("!")
                            newUser[1] = newUser[1].lower()


                            correctPassword = checkAuth(newUser[1], newUser[2])
                            if correctPassword == 1:
                                onlineUsers[sock] = (str("!" + newUser[1] + "!"))
                                prt = "Online Users\n--------\n" + str(onlineUsers)
                                print(prt)
                                broadcast(server_socket, sockfd, "Currently Online Users:\n" + onlineUsers)
                                user = str(newUser[1])
                            else:
                                print("Failed Login Killing Socket!")
                                SOCKET_LIST.remove(sock)

                        elif data[:5] == "OUUR!":
                            print("Updateing Online Users")
                            print(str(onlineUsers))
                            toSend = "OUU!" + str(onlineUsers) + "END"
                            broadcast(server_socket, sock, toSend)

                        elif data[:3] == "TER":
                            del onlineUsers[sock]
                        else:
                            userToSend = str(onlineUsers[sock])
                            userToSend = userToSend[1:-1]
                            print("The Enc MSG is!")
                            print(data)
                            print("----------------")
                            if enctype == "CBC":
                                data = AESEnc.decryptCBC(data)
                                print(data)
                                print("================")
                                data = "\r" + '[' + userToSend +'] ' + data
                                data = AESEnc.encryptCBC(data)

                            elif enctype == "CFB":
                                data = AESEnc.decryptCFB(data)
                                print(data)
                                print("================")
                                data = "\r" + '[' + userToSend +'] ' + data
                                data = AESEnc.encryptCFB(data)
                            broadcastEnc(server_socket, sock, data)
                    else:
                        # remove the socket that's broken
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)

                        # catch broken connection
                        print("User Is")
                        print(sock)
                        print("-----")
                        print(onlineUsers[sock])
                        print("-----")
                        print("removeing User")
                        print("-----")
                        del onlineUsers[sock]
                        print(onlineUsers)

                        print(user)

                        print("Updateing Online Users")
                        print(str(onlineUsers))
                        toSend = "OUU!" + str(onlineUsers) + "END"
                        broadcast(server_socket, sock, toSend)


                # exception
                except:
                    print("Updateing Online Users")
                    print(str(onlineUsers))
                    toSend = "OUU!" + str(onlineUsers) + "END"
                    continue

    server_socket.close()

# broadcast chat messages to all connected clients
def broadcast (server_socket, sock, message):
    for socket in SOCKET_LIST:
        # send the message only to peer
        if socket != server_socket and socket != sock :
            try :
                socket.send(message.encode('utf-8'))
            except :
                # broken socket connection
                socket.close()
                # broken socket, remove it
                if socket in SOCKET_LIST:
                    SOCKET_LIST.remove(socket)

#Broadcase msg with full encyption
def broadcastEnc (server_socket, sock, message):
    for socket in SOCKET_LIST:
        if socket != server_socket and socket != sock :
            try :
                socket.send(message)
            except :
                socket.close()
                if socket in SOCKET_LIST:
                    SOCKET_LIST.remove(socket)




if __name__ == "__main__":

    sys.exit(chat_server())
