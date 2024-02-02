import socket
import rsa
import os
import time
import json
import pickle
import struct
import threading

def stream_read_in(cli,length,step=768*768):
    cache=b''
    while not len(cache)==length:
        if (length-len(cache))<=step:
            cache+=cli.recv(length-len(cache))
        else:
            cache+=cli.recv(step)
        #print(cache)
    return cache

def split(long_message,public_key):
  sec=100
  messages=[long_message[i:i+sec] for i in range(0,len(long_message),sec)]
  encoded_messages=[]
  for i in messages:
    encoded_messages.append(rsa.encrypt(i,public_key))
  encoded_messages=pickle.dumps(encoded_messages)
  encoded_messages_len=struct.pack("=L",len(encoded_messages))
  return [encoded_messages_len,encoded_messages]


control=True
last_number=-1
public_key,private_key=rsa.newkeys(1024)
encoded_public_key=pickle.dumps(public_key)
encoded_public_key_len=struct.pack("=L",len(encoded_public_key))
with open('account.json') as f:
  usrname,key_password=json.load(f)
os.remove('account.json')
with open('disposition.json','rb') as d:
  ip,pro=pickle.load(d)
with open('sever.json','rb') as se:
  ser_name,ser_port=pickle.load(se)
usrname=usrname.encode()
key_password=key_password.encode()
name_len=struct.pack("=L",len(usrname))
key_len=struct.pack("=L",len(key_password))
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
      lenth=struct.pack("=L",len(cont))
      s.send(lenth)
      s.send(cont)
      sever_encoded_public_key_len=struct.unpack("=L",stream_read_in(s,4,step=4))[0]
      sever_encoded_public_key=stream_read_in(s,sever_encoded_public_key_len,step=4)
      sever_public_key=pickle.loads(sever_encoded_public_key)
      encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
      encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
      lenth=struct.pack("=L",len(encrypted_usrname))
      s.send(lenth)
      s.send(encrypted_usrname)
      lenth=struct.pack("=L",len(encrypted_key_password))
      s.send(lenth)
      s.send(encrypted_key_password)
      cmd=stream_read_in(s,1,step=4).decode()
      if cmd=='T':
        s.send(encoded_public_key_len)
        s.send(encoded_public_key)
        s.send(struct.pack('f',float(last_number)))
        return_list_len=struct.unpack("=L",stream_read_in(s,4,step=4))[0]
        return_list=stick(stream_read_in(s,return_list_len,step=4),private_key)
        last_number=int(struct.unpack('f',stream_read_in(s,4,step=4))[0])
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
