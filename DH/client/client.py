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
import json
from Crypto.Util.number import getPrime, getRandomNBitInteger, long_to_bytes


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


def send_file(path, host, port, numb_conn=1):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        threads = []
        address_num = []
        while len(address_num) < (numb_conn - 0.01):
            s.listen(numb_conn)
            print("waiting for connections")
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

    ##### check if its my package


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
    CLIENT_PORTS = [64123,63219]


    # get the client ip
    client_ip = str(input('Client ID: '))
    if client_ip == '1':
        CLIENT_PORT = 64123
        OTHER_PORT = 63219
    else:
        CLIENT_PORT = 63219
        OTHER_PORT = 64123



    # path
    cwd = os.getcwd()
    plainPath = os.path.join(cwd, "plaintext.txt")
    cipherPath = os.path.join(cwd, "ciphertext.txt")
    public_key_path = os.path.join(cwd, "public_key.txt")
    systemconfiPath = os.path.join(cwd, "system_confi.txt")
    private_key_path = os.path.join(cwd, "private_key.txt")

    ##########################################################################

    print("="*80)
    print(" "*20 +"[RECEIVE SYSTEM CONFIGURATION]")
    str(input('Ready to receive system configurations? y/n :'))
    try:
        os.remove(systemconfiPath)
    except OSError:
        pass
    receive_file(systemconfiPath, HOST, PORT)
    system_confi = eval(read_file(systemconfiPath, 'r'))
    key_size = int(system_confi['key_size'])
    block_size = int(system_confi['block_size'])
    print('-'*80)
    print(system_confi)
    print("="*80)

    ##########################################################################

    #print("="*80)
    print(" "*20 +"[GENERATE KEYS]")
    str(input('Ready to generate keys? y/n :'))
    private_key_c = getRandomNBitInteger(32)
    private_key_i = getRandomNBitInteger(32)
    private_key = {'kc':private_key_c, 'ki':private_key_i}
    with open(private_key_path, 'w') as file:
        file.write(json.dumps(private_key))

    gen_public_key(system_confi, private_key, public_key_path, client_ip)
    print('Saved private key in {}'.format(private_key_path))
    print('Saved public key key in {}'.format(public_key_path))
    #print("="*80)

     ##########################################################################

    #print("="*80)
    print(" "*20 +"[BROADCAST PUBLIC KEY]")
    str(input('Ready to broadcast public keys? y/n :'))
    # broadcast public key files to clients
    #print(" " * 5 +'share public keys with server...')
    # revise the code here as broadcast
    send_file(public_key_path, HOST, CLIENT_PORT)
    print('Done!')
    print("="*80)

    ##########################################################################

    ##########################################################################

    print("="*80)
    print(" "*20 +"[RECEIVE PUBLIC KEY]")
    str(input('Ready to receive public keys from server? y/n :'))
    # load the public key table, it is a list
    # revise the code here: establish a table of publish keys
    receive_file(public_key_path, HOST, PORT)
    #public_key_list.append(public_key)
    rearrage_public_key(public_key_path)

    print('Done!')

    #print('-'*60)
    #print(tabulate(public_key_list, headers=["ip","public_key_c", "public_key_i"]))
    #print('-'*60)

    print("="*80)

   

    #print("="*80)
    print(" "*20 +"[RECEIVE FILES]")
    str(input('Ready to receive files? y/n :'))
    try:
        os.remove(cipherPath)
    except OSError:
        pass

    receive_file(cipherPath, HOST, PORT)

    print('Done!')
    print("="*80)

    ##########################################################################

    #print("="*80)
    print(" "*20 +"[DECRYPT FILES]")
    # extract client's public key
    public_key_list = eval(read_file(public_key_path, 'r'))
    public_key = public_key_list['0']
    public_key_c = public_key[0]
    public_key_i = public_key[1]

    private_key = eval(read_file(private_key_path, 'r'))
    private_key_c = private_key['kc']
    private_key_i = private_key['ki']

    system_confi = eval(read_file(systemconfiPath, 'r'))

    # 
    p = system_confi['p_g_c'][0]
    key_c = long_to_bytes(pow(public_key_c, private_key_c, p))
    p = system_confi['p_g_i'][0]
    key_i = long_to_bytes(pow(public_key_i, private_key_i, p))
    #
    cipher_message = eval(read_file(cipherPath, "r"))
    key = {'iv': cipher_message['iv'], 'kc':key_c, 'ki':key_i}
    print(key)
    
    print('Decrypt message...')
    plaintext = decrypt(key, system_confi['block_size'], cipher_message)
    with open(plainPath, "wb") as f:
        f.write(base64.encodebytes(plaintext))
    print(" "*5 + 'done.')

    cwd = os.getcwd()
    downloadPath = os.path.join(cwd, cipher_message['file_name'])

    with open(downloadPath, 'wb') as file:
        file.write(plaintext)

    mac_c = encrypt(key, system_confi['block_size'], plaintext)
    if mac_c == cipher_message['MAC']:
        print(" "*5 + 'file is intact.')
        
    else:
        print(" "*5 + "file is modified.")
            
    ##########################################################################

            
