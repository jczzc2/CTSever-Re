import socket
import rsa
import os
import time
import json
import pickle
import struct
import threading
control=True
last_number=-1
public_key,private_key=rsa.newkeys(1024)
encoded_public_key=pickle.dumps(public_key)
encoded_public_key_len=struct.pack('L',len(encoded_public_key))
with open('account.json') as f:
  usrname,key_password=json.load(f)
os.remove('account.json')
with open('disposition.json','rb') as d:
  ip,pro=pickle.load(d)
with open('sever.json','rb') as se:
  ser_name,ser_port=pickle.load(se)
usrname=usrname.encode()
key_password=key_password.encode()
name_len=struct.pack('L',len(usrname))
key_len=struct.pack('L',len(key_password))
def stick(encoded_messages,private_key):
  encoded_messages=pickle.loads(encoded_messages)
  encoded_long_message=b''
  for i in encoded_messages:
    message=rsa.decrypt(i,private_key)
    encoded_long_message+=message
  long_message=pickle.loads(encoded_long_message)
  return long_message
def pr():
  global last_number
  while True:
    #last_number=struct.pack('f',last_number)
    if control:
      s=socket.socket(ip,pro)
      s.connect((ser_name,ser_port))
      cont='get_message'.encode()
      lenth=struct.pack('L',len(cont))
      s.send(lenth)
      s.send(cont)
      sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
      sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
      sever_public_key=pickle.loads(sever_encoded_public_key)
      encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
      encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
      lenth=struct.pack('L',len(encrypted_usrname))
      s.send(lenth)
      s.send(encrypted_usrname)
      lenth=struct.pack('L',len(encrypted_key_password))
      s.send(lenth)
      s.send(encrypted_key_password)
      cmd=s.recv(1).decode()
      if cmd=='T':
        s.send(encoded_public_key_len)
        s.send(encoded_public_key)
        s.send(struct.pack('f',float(last_number)))
        return_list_len=struct.unpack('L',s.recv(4))[0]
        return_list=stick(s.recv(return_list_len),private_key)
        last_number=int(struct.unpack('f',s.recv(4))[0])
        for i in return_list:
          for sentence in i:
            print(sentence)
          print('---------------------')
    else:break
    time.sleep(0.5)
def commander():
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
  s.bind(('127.0.0.1',3072))
  cmd=s.recvfrom(10)
  global control
  control=False
prt=threading.Thread(target=pr)
commandert=threading.Thread(target=commander)
commandert.start()
prt.start()
commandert.join()
prt.join()
