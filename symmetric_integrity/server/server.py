#!/usr/bin/env python
# coding: utf-8
# pip install pycryptodome
# _*_ utf-8 _*_
import socket
from threading import Thread
import base64
import os
import pandas as pd
from tabulate import tabulate
from crypto import*
from Crypto.Util.number import getPrime, getRandomNBitInteger, long_to_bytes
import json


class ServerSend(Thread):  # Derived from Thread

    def __init__(self, ip, port, conn, path):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.conn = conn
        self.path = path
        print("New server socket thread started for " + ip + ":" + str(port))

    def run(self):
        with open(self.path, 'rb') as f:
            size_send = f.read(1024)
            while size_send:
                self.conn.sendall(size_send)
                size_send = f.read(1024)


def broadcast(path, host, port, numb_conn=2):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        threads = []
        address_num = []
        while len(address_num) < (numb_conn - 0.01):
            s.listen(numb_conn)
            print("server is waiting for connections")
            (conn, (ip, port)) = s.accept()
            if ip not in address_num:
                print('Connected by ', (ip,port))
                address_num.append((ip,port))
                new_thread = ServerSend(ip, port, conn, path)
                new_thread.start()
                threads.append(new_thread)
            else:
                pass
        for t in threads:
            t.join()

def send_file(path, host, port, numb_conn=1):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        threads = []
        address_num = []
        while len(address_num) < (numb_conn - 0.01):
            s.listen(numb_conn)
            print("server is waiting for connections")
            (conn, (ip, port)) = s.accept()
            if ip not in address_num:
                print('Connected by ', (ip,port))
                address_num.append(ip)
                new_thread = ServerSend(ip, port, conn, path)
                new_thread.start()
                threads.append(new_thread)
            else:
                pass
        for t in threads:
            t.join()


def receive_file(path, HOST, PORT):
    ADDR = (HOST, PORT)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.connect(ADDR)
    with open(path, "ab") as f:
        while True:
            data = client.recv(1024)
            if not data:
                break;
            f.write(data)
            #break
    f.close()
    print("received")
    client.close()



def read_file(path, mode):
    '''
    rb: read bytes, rt: read text
    '''
    with open(path, mode) as file:
        x = file.read()
        return x



if __name__ == "__main__":

    # ip adrress
    HOST = "127.0.0.1"
    PORT = 65431
    CLIENT_PORT = [64123,63219]


    #############################################################################
    # path
    cwd = os.getcwd()
    plainPath = os.path.join(cwd, "plaintext.txt")
    cipherPath = os.path.join(cwd, "ciphertext.txt")
    public_key_path = os.path.join(cwd, "public_key.txt")
    private_key_path = os.path.join(cwd, "private_key.txt")
    systemconfiPath = os.path.join(cwd, "system_confi.txt")


    # print out the public knowledge
    print("="*80)
    print(" "*20 +"[SYSTEM INFO]")
    print('Cryto system in use: ')
    print(" "*5+ 'AES & CBC mode with')
    #  (can be 128, 192, or 256})
    #blocksize must be 16, 24, or 32.  

    key_size = int(input(" "*10 + "key size (128, 192, or 256 bits) = "))
    # can be 128 bits only for AES
    block_size = int(input(" "*10 + "block size (16, 24, or 32 bytes)) = "))


   

    num_clients = int(input('Broadcast system configurations to {} clients: '))
    system_confi = {'cipher': 'AES', 'mode': 'CBC', 'key_size': key_size, 'block_size': block_size}
    with open(systemconfiPath, 'w') as file:
        file.write(json.dumps(system_confi))
    ########## revise the code here
    broadcast(systemconfiPath, HOST, PORT, num_clients)
    print("="*80)

    ##########################################################################

    # ask the server to input its private key a for both confidentiality and integrity
    #print("="*80)
    #print(" "*20 +"[GET PRIVATE KEY]")
    #print("To encrypt files:")
    #private_key_c = int(input(" " * 5 + "please enter the private key for confidentiality (an integer): "))
    #private_key_i = int(input(" " * 5 + "please enter the private key for integrity (an integer): "))
    # store private key locally
    #print("="*80)


    ##########################################################################   

    #print("="*80)
    print(" "*20 +"[GENERATE KEYS]")
    str(input('Ready to generate private keys? y/n :'))

    private_key_c = getRandomNBitInteger(key_size)
    private_key_i = getRandomNBitInteger(key_size)

    private_key = {'kc':private_key_c, 'ki': private_key_i}
    with open(private_key_path, 'w') as file:
        file.write(json.dumps(private_key))
    print('Saved private key in ', private_key_path)
    print("="*80)


    ##########################################################################


    #print("="*80)
    print(" "*20 +"[SHARE PRIVATE KEY]")
    print('Copy private key to clients using USB drive...')
    str(input('Private key copied? y/n: '))
    # load the public key table, it is a list


    #print("="*80)
    print(" "*20 +"[SEND FILES]")
    flag = str(input('Ready to send files? y/n:'))
    filePath = os.path.join(cwd, "03.pdf")
    str(input('Path of the file to be sent: "server/03.pdf"? y/n :'))
    # load its private key
    #private_key_c, private_key_i = read_file()
    plaintext = read_file(filePath, 'rb')
    with open(plainPath,'wb') as file:
        file.write(plaintext)
    #print(plaintext)
    system_confi = eval(read_file(systemconfiPath, 'r'))
    private_key = eval(read_file(private_key_path, 'r'))
    key_c = long_to_bytes(private_key['kc'])
    key_i = long_to_bytes(private_key['ki'])
    iv = long_to_bytes(getRandomNBitInteger(key_size))

    key = {'iv':iv, 'kc':key_c, 'ki': key_i}
    

        ######### revise 
    ciphertext, MAC = encrypt(key, system_confi['block_size'], plaintext)

        #print(ciphertext, MAC)

        # concantecate ciphertext and MAC
    ciphertext, MAC = encrypt(key, system_confi['block_size'], plaintext)
    cipher_message = {'ip':'0', 'iv':iv, 'ciphertext': ciphertext, 'MAC': MAC, 'file_name': "03.pdf"}
        #print(cipher_message)
    try:
        os.remove(cipherPath)
    except OSError:
        pass
    with open(cipherPath, 'w') as file:
        file.write(str(cipher_message))
    print(' '*5 + 'sending ciphertext to clients')
        #print(cipher_message)
    broadcast(cipherPath, HOST, PORT, num_clients)
    print("Done!")
    print('='*80)

  
        
    ##########################################################################

        

