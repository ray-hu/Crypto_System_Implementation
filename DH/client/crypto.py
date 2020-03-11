#!/usr/bin/env python
# coding: utf-8
# pip install pycryptodome
# _*_ utf-8 _*_
from py3rijndael import RijndaelCbc, ZeroPadding
import base64
import os, secrets
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime
import json


def rearrage_public_key(public_key_path):
    with open(public_key_path, 'r') as file:
        x = file.read().replace('}{', ',')

    y = eval(x)
    result = {}
    for key,value in y.items():
        if key not in result.keys():
            result[key] = value
    with open(public_key_path, 'w') as file:
        file.write(json.dumps(result))


def gen_public_key(system_confi, private_key, public_key_path, client_ip):
    """
    generate key
    :return:
    """
    private_key_c = private_key['kc']
    private_key_i = private_key['ki']
    p = system_confi['p_g_c'][0]
    g = system_confi['p_g_c'][1]
    public_key_c = pow(g, private_key_c, p)
    del p,g

    p = system_confi['p_g_i'][0]
    g = system_confi['p_g_i'][1]
    public_key_i = pow(g, private_key_i, p)

    public_key = {client_ip: (public_key_c, public_key_i)}
    del p,g

    with open(public_key_path, 'w') as file:
        file.write(json.dumps(public_key))


def encrypt(key, block_size, plaintext):
    iv = key['iv']
    kc = key['kc']
    ki = key['ki']
    
    rijndael_cbc = RijndaelCbc(
        key=ki,  # if it is a string we can use base64.b64decode(key),
        iv=iv,
        padding=ZeroPadding(block_size),
        block_size=block_size
    )

    MAC = rijndael_cbc.encrypt(plaintext)[-block_size:]
    
    return MAC

# ---------------------receive part-----------------


def decrypt(key, block_size, cipher_message):
    """
    AES
     key,iv are the same
    mode cbc
    pkcs7
    :param key:
    :param content:
    :return:
    """
    kc = key['kc']
    iv = key['iv']
    ciphertext = cipher_message['ciphertext']

    rijndael_cbc = RijndaelCbc(
        key=kc,  # if it is a string we can use base64.b64decode(key),
        iv=iv,
        padding=ZeroPadding(block_size),
        block_size=block_size
    )


    return rijndael_cbc.decrypt(ciphertext)

            
