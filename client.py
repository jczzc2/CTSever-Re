import os
import rsa
import pickle
import json
import time
import socket
import struct
import hashlib
import tqdm
import copy
import maskpass
import traceback

def stream_read_in(cli,length):
    cache=b''
    step=768*768
    while not len(cache)==length:
        if (length-len(cache))<=step:
            cache+=cli.recv(length-len(cache))
        else:
            cache+=cli.recv(step)
        #print(cache)
    return cache

public_key,private_key=rsa.newkeys(2048)
encoded_public_key=pickle.dumps(public_key)
encoded_public_key_len=struct.pack('L',len(encoded_public_key))

def stick(encoded_messages,private_key):
  encoded_messages=pickle.loads(encoded_messages)
  encoded_long_message=b''
  for i in encoded_messages:
    message=rsa.decrypt(i,private_key)
    encoded_long_message+=message
  long_message=pickle.loads(encoded_long_message)
  return long_message

def main():
  print('enter your username and password')
  print('if you are new member,just continue with no input')
  con=True
  if input('IP(IPv6/IPv4):')=='IPv6':
    ip=socket.AF_INET6
    pro=socket.SOCK_STREAM
  else:
    ip=socket.AF_INET
    pro=socket.SOCK_STREAM
  with open('disposition.json','bw') as f:
    pickle.dump([ip,pro],f)
  ser_name=input('sever_name:')
  ser_port=input('sever_port:')
  with open('sever.json','wb') as se:
    pickle.dump([ser_name,int(ser_port)],se)
  while con:
    usrname=input('usrname:').encode()
    name=usrname.decode()
    if usrname==b'':
      con1=True
      while con1:
        print('please enter your usrname')
        usrname=input('usrname:').encode()
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='name_test'.encode()
        lenth=struct.pack('L',len(cont))
        s.send(lenth)
        s.send(cont)
        lenth=struct.pack('L',len(usrname))
        s.send(lenth)
        s.send(usrname)
        command=s.recv(1).decode()
        #print(command)
        if command=='F':
          con1=False
        else:
          print('usr_name_already_exists')
      print('please_enter_your_password')
      password=maskpass.askpass(prompt='password:',mask='.').encode()
      repeat_password=maskpass.askpass(prompt='password:',mask='.').encode()
      if password!=repeat_password:
          print('The password is inconsistent with the verification')
          continue
      key_password=hashlib.sha512(password).hexdigest().encode()
      s=socket.socket(ip,pro)
      s.connect((ser_name,int(ser_port)))
      cont='sign_up'.encode()
      lenth=struct.pack('L',len(cont))
      s.send(lenth)
      s.send(cont)
      time.sleep(0.5)
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
      break
    password=maskpass.askpass(prompt='password:',mask='●').encode()
    key_password=hashlib.sha512(password).hexdigest().encode()
    try:
      s=socket.socket(ip,pro)
      s.connect((ser_name,int(ser_port)))
      cont='login_in'.encode()
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
        con=False
      else:print('account error')
    except Exception as e:
      print('sever_connection_failed')
      print(e)
      traceback.print_exc()
      time.sleep(2)
  print('login_end')
  while True:
    #command=input('command:')
    try:
      command=input('command:')
      if command=='send_file':
        file_path=input('file_path:')+os.sep
        file_name=input('file_name:')
        file_path+=file_name
        if not os.path.exists(file_path):
          print('no such file')
          continue
        file_size=os.path.getsize(file_path)
        size=piece_size=1024*768
        num=piece_num=file_size//piece_size
        if file_size%piece_size>0:
          piece_num+=1
          end_size=file_size%piece_size
        else:
          piece_num
          num-=1
          end_size=piece_size
        end_size=struct.pack('L',end_size)
        piece_num=struct.pack('L',piece_num)
        piece_size=struct.pack('L',piece_size)
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='file_send'.encode()
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
          lenth=struct.pack('L',len(file_name.encode()))
          s.send(lenth)
          s.send(file_name.encode())
          s.send(piece_num)
          with open(file_path,'br') as f:
            for i in tqdm.tqdm(range(num)):
              piece=f.read(size)
              s.send(piece_size)
              #time.sleep(0.02)
              s.recv(1)
              s.send(piece)
              s.recv(1)
              #print(i)
            piece=f.read(size)
            s.send(struct.pack('L',len(piece)))
            s.recv(1)
            s.send(piece)
            s.recv(1)
            print('end')
        else:print('account error')
      elif command=='get_file':
        author=input('author:')
        file=input('file_name:')
        save_path=input('save_path:')
        if not os.path.exists(save_path):
          print('no such path')
          continue
        author_name=author.encode()
        file_name=file.encode()
        s=socket.socket(ip,pro)
        s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,False)
        s.connect((ser_name,int(ser_port)))
        cont='file_get'.encode()
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
          lenth=struct.pack('L',len(author_name))
          s.send(lenth)
          s.send(author_name)
          lenth=struct.pack('L',len(file_name))
          s.send(lenth)
          s.send(file_name)
          cmd=s.recv(1).decode()
          if cmd=='T':
            file_piece_num=struct.unpack('L',s.recv(4))[0]
            print(file_piece_num,'pieces in all')
            with open(save_path+os.sep+file,'bw') as f:
              cont=0
              for i in tqdm.tqdm(range(file_piece_num+1)):
                #lenth=0
                lenth=copy.deepcopy(struct.unpack('Q',s.recv(8))[0])
                #print(cont,'/',file_piece_num+1,'|',lenth)
                _=lenth
                s.send(b'_')
                piece=stream_read_in(s,lenth)
                f.write(piece)
                #f.flush()
                s.send('V'.encode())
                #print(i)
                #os.system('cls')
                cont+=1
              f.flush()
              f.close()
          else:
            print('no such file/author')
        else:print('account error')
      elif command=='chat':
        with open('account.json','w') as f:
          json.dump([name,key_password.decode()],f)
        if os.path.exists('test.sign'):
          os.system('start client_helper.py')
        else:
          os.system('start client_helper.exe')
        com=True
        while com:
          message=input('>>')
          if message=='exit':
            break
          message=[name,message]
          message=pickle.dumps(message)
          s=socket.socket(ip,pro)
          s.connect((ser_name,int(ser_port)))
          cont='send_message'.encode()
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
          control=s.recv(1).decode()
          if control=='T':
            sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
            sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
            sever_public_key=pickle.loads(sever_encoded_public_key)
            message=rsa.encrypt(message,sever_public_key)
            message_len=struct.pack('L',len(message))
            s.send(message_len)
            s.send(message)
          else:
            print('account error')
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.sendto('end'.encode(),('127.0.0.1',3072))
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='chat_exit'.encode()
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
        print("sever's reply") 
        print(s.recv(1).decode())
        print('exited room')
      elif command=='exit':
        break
      elif command=='cls':
        os.system('cls')
      elif command=='change_password':
        password=maskpass.askpass(prompt='password:',mask='.').encode()
        repeat_password=maskpass.askpass(prompt='password:',mask='.').encode()
        if password!=repeat_password:
          print('The password is inconsistent with the verification')
          continue
        new_key_password=hashlib.sha512(password).hexdigest().encode()
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='change_password'.encode()
        lenth=struct.pack('L',len(cont))
        s.send(lenth)
        s.send(cont)
        sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
        sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
        sever_public_key=pickle.loads(sever_encoded_public_key)
        encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
        encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
        new_encrypted_key_password=rsa.encrypt(new_key_password,sever_public_key)
        lenth=struct.pack('L',len(encrypted_usrname))
        s.send(lenth)
        s.send(encrypted_usrname)
        lenth=struct.pack('L',len(encrypted_key_password))
        s.send(lenth)
        s.send(encrypted_key_password)
        cmd=s.recv(1).decode()
        if cmd=='T':
          lenth=struct.pack('L',len(new_encrypted_key_password))
          s.send(lenth)
          s.send(new_encrypted_key_password)
      elif command=='post_publish':
        post_name=input('file_name>>')
        path=input('file_path>>')+os.sep
        topic=input('topic>>')
        intro=input('intro>>')
        if len(topic)>50 or len(intro)>200:
          print("""topic/intro too long for a post""")
          os.system('pause')
          os.system('cls')
          continue
        if not os.path.exists(path+post_name):
          print("""file/path not exists""")
          os.system('pause')
          os.system('cls')
          continue
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='add_post'.encode()
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
          with open(path+post_name,'br')as f:
            pack=pickle.dumps([topic,intro,f.read()])
            pack_lenth=struct.pack('L',len(pack))
            s.send(pack_lenth)
            time.sleep(0.01)
            s.send(pack)
      elif command=='change_acc_creatable':
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='change_acc_creatable'.encode()
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
          print(s.recv(5).decode())
        else:
          print('account_error')
      elif command=='ban_post':
        post_code=int(input('post_index>>'))
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='ban_post'.encode()
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
          s.send(struct.pack('Q',post_code))
        else:
          print('account_error')
      elif command=='add_usr':
        new_usr_name=input('new_usr_name>>').encode()
        new_usr_password=input('passwd>>').encode()
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='add_usr'.encode()
        lenth=struct.pack('L',len(cont))
        s.send(lenth)
        s.send(cont)
        sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
        sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
        sever_public_key=pickle.loads(sever_encoded_public_key)
        encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
        encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
        new_key_password=hashlib.sha512(new_usr_password).hexdigest().encode()
        new_usr_encrypted_key_password=rsa.encrypt(new_key_password,sever_public_key)
        new_usr_encrypted_usrname=rsa.encrypt(new_usr_name,sever_public_key)
        lenth=struct.pack('L',len(encrypted_usrname))
        s.send(lenth)
        s.send(encrypted_usrname)
        lenth=struct.pack('L',len(encrypted_key_password))
        s.send(lenth)
        s.send(encrypted_key_password)
        cmd=s.recv(1).decode()
        if cmd=='T':
          s.send(struct.pack('L',len(new_usr_encrypted_usrname)))
          time.sleep(0.03)
          s.send(new_usr_encrypted_usrname)
          cmd=s.recv(1).decode()
          if cmd=='T':
            lenth=struct.pack('L',len(new_usr_encrypted_key_password))
            s.send(lenth)
            s.send(new_usr_encrypted_key_password)
          else:
            print('usr_already_exists')
        else:
          print('account_error')
          continue
      elif command=='add_executive':
        new_usr_name=input('new_executive_name>>').encode()
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='add_executive'.encode()
        lenth=struct.pack('L',len(cont))
        s.send(lenth)
        s.send(cont)
        sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
        sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
        sever_public_key=pickle.loads(sever_encoded_public_key)
        encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
        encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
        #new_key_password=hashlib.sha512(new_usr_password).hexdigest().encode()
        #new_usr_encrypted_key_password=rsa.encrypt(new_key_password,sever_public_key)
        new_usr_encrypted_usrname=rsa.encrypt(new_usr_name,sever_public_key)
        lenth=struct.pack('L',len(encrypted_usrname))
        s.send(lenth)
        s.send(encrypted_usrname)
        lenth=struct.pack('L',len(encrypted_key_password))
        s.send(lenth)
        s.send(encrypted_key_password)
        cmd=s.recv(1).decode()
        if cmd=='T':
          s.send(struct.pack('L',len(new_usr_encrypted_usrname)))
          time.sleep(0.03)
          s.send(new_usr_encrypted_usrname)
          cmd=s.recv(1).decode()
          if cmd=='T':
            print('successfully_added_an_executive')
          else:
            print('usr_not_exists')
        else:
          print('account_error')
          continue
      elif command=='del_executive':
        new_usr_name=input('del_executive_name>>').encode()
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='del_executive'.encode()
        lenth=struct.pack('L',len(cont))
        s.send(lenth)
        s.send(cont)
        sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
        sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
        sever_public_key=pickle.loads(sever_encoded_public_key)
        encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
        encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
        #new_key_password=hashlib.sha512(new_usr_password).hexdigest().encode()
        #new_usr_encrypted_key_password=rsa.encrypt(new_key_password,sever_public_key)
        new_usr_encrypted_usrname=rsa.encrypt(new_usr_name,sever_public_key)
        lenth=struct.pack('L',len(encrypted_usrname))
        s.send(lenth)
        s.send(encrypted_usrname)
        lenth=struct.pack('L',len(encrypted_key_password))
        s.send(lenth)
        s.send(encrypted_key_password)
        cmd=s.recv(1).decode()
        if cmd=='T':
          s.send(struct.pack('L',len(new_usr_encrypted_usrname)))
          time.sleep(0.03)
          s.send(new_usr_encrypted_usrname)
          cmd=s.recv(1).decode()
          if cmd=='T':
            print('successfully_deled_an_executive')
          else:
            print('executive_not_exists')
        else:
          print('account_error')
          continue
      elif command=='ban_account':
        ban_usr_name=input('ban_account_name>>').encode()
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='ban_account'.encode()
        lenth=struct.pack('L',len(cont))
        s.send(lenth)
        s.send(cont)
        sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
        sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
        sever_public_key=pickle.loads(sever_encoded_public_key)
        encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
        encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
        #new_key_password=hashlib.sha512(new_usr_password).hexdigest().encode()
        #new_usr_encrypted_key_password=rsa.encrypt(new_key_password,sever_public_key)
        ban_usr_encrypted_usrname=rsa.encrypt(ban_usr_name,sever_public_key)
        lenth=struct.pack('L',len(encrypted_usrname))
        s.send(lenth)
        s.send(encrypted_usrname)
        lenth=struct.pack('L',len(encrypted_key_password))
        s.send(lenth)
        s.send(encrypted_key_password)
        cmd=s.recv(1).decode()
        if cmd=='T':
          s.send(struct.pack('L',len(ban_usr_encrypted_usrname)))
          time.sleep(0.03)
          s.send(ban_usr_encrypted_usrname)
          cmd=s.recv(1).decode()
          if cmd=='T':
            print('successfully_banned_an_account')
          else:
            print('account_not_exists')
        else:
          print('account_error')
          continue
      elif command=='unban_account':
        unban_usr_name=input('unban_account_name>>').encode()
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='unban_account'.encode()
        lenth=struct.pack('L',len(cont))
        s.send(lenth)
        s.send(cont)
        sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
        sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
        sever_public_key=pickle.loads(sever_encoded_public_key)
        encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
        encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
        #new_key_password=hashlib.sha512(new_usr_password).hexdigest().encode()
        #new_usr_encrypted_key_password=rsa.encrypt(new_key_password,sever_public_key)
        unban_usr_encrypted_usrname=rsa.encrypt(unban_usr_name,sever_public_key)
        lenth=struct.pack('L',len(encrypted_usrname))
        s.send(lenth)
        s.send(encrypted_usrname)
        lenth=struct.pack('L',len(encrypted_key_password))
        s.send(lenth)
        s.send(encrypted_key_password)
        cmd=s.recv(1).decode()
        if cmd=='T':
          s.send(struct.pack('L',len(unban_usr_encrypted_usrname)))
          time.sleep(0.03)
          s.send(unban_usr_encrypted_usrname)
          cmd=s.recv(1).decode()
          if cmd=='T':
            print('successfully_unbanned_an_account')
          else:
            print('account_not_exists')
        else:
          print('account_error')
          continue
      elif command=='bbs':
        os.system('cls')
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='get_bbs_end'.encode()
        lenth=struct.pack('L',len(cont))
        s.send(lenth)
        s.send(cont)
        sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
        sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
        sever_public_key=pickle.loads(sever_encoded_public_key)
        encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
        encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
        #new_encrypted_key_password=rsa.encrypt(new_key_password,sever_public_key)
        lenth=struct.pack('L',len(encrypted_usrname))
        s.send(lenth)
        s.send(encrypted_usrname)
        lenth=struct.pack('L',len(encrypted_key_password))
        s.send(lenth)
        s.send(encrypted_key_password)
        cmd=s.recv(1).decode()
        if cmd=='T':
          pointer_end=struct.unpack('Q',s.recv(8))[0]
          pointer=pointer_end
          print('last_post',pointer)
        else:
          print('account_error')
          continue
        while True:
          cmd=input('post\\command>>')
          if cmd=='get_post':
            post_code=int(input('post\\post_index>>'))
            if post_code<0 or post_code>pointer_end:
              print('index out of range')
              continue
            s=socket.socket(ip,pro)
            s.connect((ser_name,int(ser_port)))
            cont='get_post'.encode()
            lenth=struct.pack('L',len(cont))
            s.send(lenth)
            s.send(cont)
            sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
            sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
            sever_public_key=pickle.loads(sever_encoded_public_key)
            encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
            encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
            #new_encrypted_key_password=rsa.encrypt(new_key_password,sever_public_key)
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
              s.send(struct.pack('Q',post_code))
              encrypted_post_len=struct.unpack('L',s.recv(4))[0]
              #post=stick(s.recv(encrypted_post_len),private_key)
              post=stick(stream_read_in(s,encrypted_post_len),private_key)
              os.system('cls')
              print('-'*50)
              print(post[0])
              print('author:',post[1],'|','post_index',post_code)
              print('Intro:\n',post[2],'\n')
              print('Content:')
              print(post[3].decode())
            else:
              print('account_error')
              continue
          elif cmd=='return':
            s=socket.socket(ip,pro)
            s.connect((ser_name,int(ser_port)))
            cont='get_bbs_end'.encode()
            lenth=struct.pack('L',len(cont))
            s.send(lenth)
            s.send(cont)
            sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
            sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
            sever_public_key=pickle.loads(sever_encoded_public_key)
            encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
            encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
            #new_encrypted_key_password=rsa.encrypt(new_key_password,sever_public_key)
            lenth=struct.pack('L',len(encrypted_usrname))
            s.send(lenth)
            s.send(encrypted_usrname)
            lenth=struct.pack('L',len(encrypted_key_password))
            s.send(lenth)
            s.send(encrypted_key_password)
            cmd=s.recv(1).decode()
            if cmd=='T':
              pointer_end=struct.unpack('Q',s.recv(8))[0]
              pointer=pointer_end
              print('last_post',pointer)
            else:
              print('account_error')
              continue
          elif cmd=='ask_post':
            s=socket.socket(ip,pro)
            s.connect((ser_name,int(ser_port)))
            cont='ask_post'.encode()
            lenth=struct.pack('L',len(cont))
            s.send(lenth)
            s.send(cont)
            sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
            sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
            sever_public_key=pickle.loads(sever_encoded_public_key)
            encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
            encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
            #new_encrypted_key_password=rsa.encrypt(new_key_password,sever_public_key)
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
              s.send(struct.pack('Q',pointer))
              encrypted_bbs_list_len=struct.unpack('L',s.recv(4))[0]
              #encrypted_bbs_list=s.recv(encrypted_bbs_list_len)
              encrypted_bbs_list=stream_read_in(s,encrypted_bbs_list_len)
              bbs_list=stick(encrypted_bbs_list,private_key)
              for item in bbs_list:
                print('-'*45)
                print('topic:',item[1],'|','post_index',item[0])
                print('author:',item[2])
              pointer-=10
              if pointer<0:
                pointer=pointer_end
            else:
              print('account_error')
              continue
          elif cmd=='exit':
            os.system('cls')
            break
    except:
      #print(e)
      traceback.print_exc()
      time.sleep(2)
