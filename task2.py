#!/usr/bin/python3

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from urllib.parse import quote, unquote
import binascii

def submit(arb, cbc):
	# generate string
	gen_str = "userid=456;userdata=" + arb + ";session-id=31337"
	# url encode the string
	gen_str = quote(gen_str)
	# convert to bytestring
	gen_str = gen_str.encode('utf-8')
	# pad with pkcs7 to blocks of size 128
	gen_str = pad(gen_str, 128, style = 'pkcs7')
	# encrypt padded string using AES-128-CBC
	return cbc.encrypt(gen_str)

def verify(enc, cbc):
	# decrypt the string
	session = cbc.decrypt(enc)
	# unpad the string
	session = unpad(session, 128, style = 'pkcs7')
	# convert to real string
	session = session.decode('utf-8')
	# # url decode the string
	# session = unquote(session)
	return admin_check(session)

def admin_check(string):
	for i in range(0, len(string)):
		if string[i] == ";":
			if string[i:i + 12] == ";admin=true;":
				return True
	return False

def byte_xor(b1, b2):
    return bytearray([a ^ b for a, b in zip(b1, b2)])

def bit_flip_attack(encrypted):
	inject = b";admin=true;"
	i = 0
	
	encrypted = bytearray(encrypted)

	for b in byte_xor(bytes(encrypted[:12]), inject):
		encrypted[i] = b
		i += 1

	return bytes(encrypted)

def main():
	# generate new AES object
	key = os.urandom(16)
	iv = os.urandom(16)
	cbc1 = AES.new(key, AES.MODE_CBC, iv)
	cbc2 = AES.new(key, AES.MODE_CBC, iv)

	user_input = input("enter an arbitrary string: ")
	encrypted = submit(user_input, cbc1)
	encrypted = bit_flip_attack(encrypted)
	result = verify(encrypted, cbc2)

	if result:
		print("admin")
	else:
		print("not admin")

main()

# use the pdf sent by nicole pg 62
