import socket
import pickle
import os
import time
import struct
import json
import _thread
import threading
import traceback
import rsa

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

def waiters_manager():
    global waiters
    global public_key,private_key,encoded_public_key,encoded_public_key_len
    key_changed=True
    while True:
        cont=0
        bre=False
        lock.acquire()
        for waiter in waiters:
            if not waiter.is_alive():
                del waiters[cont]
                bre=True
                break
            cont+=1
        lock.release()
        if key_changed and len(waiters)==0:
            public_key_1,private_key_1=rsa.newkeys(2048)
            encoded_public_key_1=pickle.dumps(public_key_1)
            encoded_public_key_len_1=struct.pack("=L",len(encoded_public_key_1))
            key_changed=False 
        if not bre:
            if len(waiters)==0 and not key_changed:
                lock.acquire()
                encoded_public_key=encoded_public_key_1
                encoded_public_key_len=encoded_public_key_len_1
                private_key=private_key_1
                lock.release()
                key_changed=True
            time.sleep(5)

def handler(c,addr):
  global names
  global passwords
  global bbs_end_code
  global account_creatable
  global executives
  global banned_accounts
  try:
    print(addr,end=' ')
    print('accept')
    lenth=struct.unpack('=L',stream_read_in(c,4,step=4))[0]
    con=stream_read_in(c,lenth,step=lenth).decode()
    if con=='name_test':
      name_len=struct.unpack('=L',stream_read_in(c,4,step=4))[0]
      name=c.recv(name_len).decode()
      if name in names:
        c.send('T'.encode())
        c.close()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='sign_up':
      if not account_creatable:
        c.close()
        return False
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(c.recv(stream_read_in(c,name_len,step=4)),private_key).decode()
      if name in names:
        c.close()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      #
      lock.acquire()
      names.append(name)
      passwords[name]=key
      with open('names.json','w') as f:
        json.dump(names,f)
      with open('passwords.json','w') as f:
        json.dump(passwords,f)
      os.mkdir('files'+os.sep+name)
      lock.release()
    elif con=='login_in':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or (name in banned_accounts):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send('T'.encode())
        c.close()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='file_send':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or (name in banned_accounts):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send(b'T')
        file_name_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        file_name=stream_read_in(c,file_name_lenth,step=4).decode()
        file_piece_num=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        with open('files'+os.sep+name+os.sep+file_name,'bw') as f:
          for i in range(file_piece_num):
            lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
            #c.close()
            c.send(b'_')
            piece=stream_read_in(c,lenth)
            print(addr,':',len(piece))
            f.write(piece)
            #f.flush()
            c.send('V'.encode())
          """
          lenth=struct.unpack("=L",c.recv(4))[0]
          print(addr,':',lenth)
          c.send(b'_')
          piece=stream_read_in(c,lenth)
          f.write(piece)
          f.flush()
          c.send('V'.encode())
          """
        c.close()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='file_get':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or (name in banned_accounts):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send('T'.encode())
        author_name_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        author_name=c.recv(author_name_lenth).decode()
        file_name_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        file_name=c.recv(file_name_lenth).decode()
        if os.path.exists('files'+os.sep+author_name+os.sep+file_name) or (author_name in banned_accounts):
          c.send('T'.encode())
          file_size=os.path.getsize('files'+os.sep+author_name+os.sep+file_name)
          size=piece_size=1024*768
          num=piece_num=file_size//piece_size
          if file_size%piece_size>0:
            piece_num+=1
            #num+=1
            end_size=file_size%piece_size
          else:
            #piece_num-=1
            num-=1
            end_size=piece_size
          end_size=struct.pack("=L",end_size)
          piece_num=struct.pack("=L",piece_num)
          piece_size=struct.pack("=L",piece_size)
          c.send(piece_num)
          with open('files'+os.sep+author_name+os.sep+file_name,'br') as f:
            for i in range(num+1):
              piece=f.read(size)
              lenth=struct.pack("=Q",len(piece))
              c.send(lenth)
              time.sleep(0.02)
              stream_read_in(c,1,step=1)
              c.send(piece)
              stream_read_in(c,1,step=1)
              print(addr,struct.unpack("=Q",lenth)[0],len(lenth))
              #print(i)
            piece=f.read(size)
            c.send(struct.pack("=Q",len(piece)))
            stream_read_in(c,1,step=1)
            c.send(piece)
            stream_read_in(c,1,step=1)
            print(addr,len(piece))
            #print('end')
          c.close()
        else:
          c.send('F'.encode())
          c.close()
        c.close()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='send_message':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or (name in banned_accounts):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send('T'.encode())
        c.send(encoded_public_key_len)
        c.send(encoded_public_key)
        message_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        #message=c.recv(message_len)
        message=stream_read_in(c,message_len)
        c.close()
        message=rsa.decrypt(message,private_key)
        message=pickle.loads(message)
        print(message)
        chat_messages.append(message)
      else:
        c.send('F'.encode())
        c.close()
    elif con=='get_message':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or (name in banned_accounts):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send('T'.encode())
        client_public_key_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        client_public_key=pickle.loads(stream_read_in(c,client_public_key_len,step=4))
        end_num=int(struct.unpack('f',stream_read_in(c,4,step=4))[0])
        new_end_num=float(len(chat_messages)-1)
        if end_num==0:
          if len(chat_messages)<=1:
            return_list=[]
          else:
            return_list=[chat_messages[0],chat_messages[-1]]
        else:
          return_list=chat_messages[end_num:]
          del return_list[0]
        new_end_num=struct.pack('f',new_end_num)
        return_list=pickle.dumps(return_list)
        return_list_len,return_list=split(return_list,client_public_key)
        c.send(return_list_len)
        c.send(return_list)
        c.send(new_end_num)
        c.close()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='chat_exit':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or (name in banned_accounts):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send('T'.encode())
        c.close()
        chat_messages.append(['system',name+' escaped'])
        print(str(['system',name+' escaped']))
      else:
        c.send('F'.encode())
        c.close()
    elif con=='change_password':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or (name in banned_accounts):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send('T'.encode())
        key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
        c.close()
        lock.acquire()
        passwords[name]=key
        lock.release()
        with open('passwords.json','w') as f:
          json.dump(passwords,f)
      else:
        c.send('F'.encode())
        c.close()
    elif con=='add_post':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or (name in banned_accounts):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send('T'.encode())
        pack_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        pack=pickle.loads(stream_read_in(c,pack_len))
        c.close()
        topic,intro,content=pack
        #bbs.append((topic,name))
        path='posts'+os.sep+'{}-{}'.format(time.localtime().tm_mon,time.localtime().tm_mday)
        file_name='{}-{}-{}.post'.format(name,topic,time.time())
        if not os.path.exists(path):
          os.mkdir(path)
        with open(path+os.sep+file_name,'bw')as f:
          f.write(pickle.dumps([topic,name,intro,content]))
          f.flush()
        lock.acquire()
        try:
          bbs.append([bbs_end_code,topic,name,path+os.sep+file_name])
          with open('community_bbs.json','w') as f:
            json.dump(bbs,f)
          bbs_end_code+=1
          with open('bbs_len.json','w') as f:
            json.dump(bbs_end_code,f)
            f.flush()
          lock.release()
        except Exception as e:
          traceback.print_exc()
          lock.release()
        print(bbs)
      else:
        c.send('F'.encode())
        c.close()
    elif con=='ask_post':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or (name in banned_accounts):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send(b'T')
        client_public_key_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        client_public_key=pickle.loads(stream_read_in(c,client_public_key_len,step=4))
        #bbs
        #bbs_end_code
        client_pointer=struct.unpack("=Q",stream_read_in(c,8,step=4))[0]
        if client_pointer-10>=0:
          bbs_list=bbs[client_pointer:client_pointer-10:-1]
        elif client_pointer==0:
          bbs_list=[bbs[0],]
        else:
          bbs_list=bbs[client_pointer:0:-1]
        print(bbs_list)
        encoded_bbs_list=pickle.dumps(bbs_list)
        encrypted_bbs_list_len,encrypted_bbs_list=split(encoded_bbs_list,client_public_key)
        c.send(encrypted_bbs_list_len)
        c.send(encrypted_bbs_list)
        c.close()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='get_post':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or (name in banned_accounts):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send(b'T')
        client_public_key_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        client_public_key=pickle.loads(stream_read_in(c,client_public_key_len,step=4))
        post_code=struct.unpack("=Q",stream_read_in(c,8,step=4))[0]
        post_information=bbs[post_code]
        path=post_information[3]
        with open(path,'br') as f:
          post=pickle.loads(f.read())
        encoded_post=pickle.dumps(post)
        encrypted_post_len,encrypted_post=split(encoded_post,client_public_key)
        c.send(encrypted_post_len)
        c.send(encrypted_post)
        c.close()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='get_bbs_end':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or (name in banned_accounts):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send(b'T')
        c.send(struct.pack("=Q",bbs_end_code-1))
        c.close()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='change_acc_creatable':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if ((name not in names) or (name in banned_accounts)) or (True and (name not in admin)):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send(b'T')
        account_creatable= not account_creatable
        if account_creatable:
          c.send(b'True ')
        else:
          c.send(b'False')
        c.close()
        with open('account_creatable.json','w') as f:
          json.dump(account_creatable,f)
      else:
        c.send('F'.encode())
        #
    elif con=='ban_post':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if (name not in names) or ((name not in executives) and (name not in admin)):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send(b'T')
        post_index=struct.unpack("=Q",stream_read_in(c,8,step=4))[0]
        print('lock_bbs')
        lock.acquire()
        try:
          bbs[post_index]=[post_index,'banned_post',name,bbs[post_index][3]]
          with open(bbs[post_index][3],'wb') as f:
            f.write(pickle.dumps([bbs[post_index][1],bbs[post_index][2],'This post is banned',b'This post is banned']))
          with open('community_bbs.json','w') as f:
            json.dump(bbs,f)
          lock.release()
        except:
          traceback.print_exc()
          lock.release()
        c.close()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='add_usr':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if ((name not in names) or (name in banned_accounts)) or (name not in admin):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send(b'T')
        new_usr_name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        new_usr_name=rsa.decrypt(stream_read_in(c,new_usr_name_len,step=4),private_key).decode()
        if new_usr_name in names:
          c.send(b'F')
          c.close()
          return False
        c.send(b'T')
        new_usr_key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        new_usr_key=rsa.decrypt(stream_read_in(c,new_usr_key_lenth,step=4),private_key).decode()
        print('adim_adding_usr')
        c.close()
        lock.acquire()
        try:
          names.append(new_usr_name)
          passwords[new_usr_name]=new_usr_key
          with open('names.json','w') as f:
            json.dump(names,f)
          with open('passwords.json','w') as f:
            json.dump(passwords,f)
          os.mkdir('files'+os.sep+name)
          lock.release()
        except:
          traceback.print_exc()
          lock.release()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='add_executive':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if ((name not in names) or (name in banned_accounts)) or (name not in admin):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send(b'T')
        new_executive_name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        new_executive_name=rsa.decrypt(stream_read_in(c,new_executive_name_len,step=4),private_key).decode()
        if not new_executive_name in names:
          c.send(b'F')
          c.close()
          return False
        c.send(b'T')
        c.close()
        lock.acquire()
        try:
          cache=set(executives)
          cache.add(new_executive_name)
          executives=list(cache)
          with open('executives.json','w') as f:
            json.dump(executives,f)
          print(executives)
          lock.release()
        except:
          traceback.print_exc()
          lock.release()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='del_executive':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if ((name not in names) or (name in banned_accounts)) or (name not in admin):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send(b'T')
        new_executive_name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        new_executive_name=rsa.decrypt(c.recv(new_executive_name_len),private_key).decode()
        if not new_executive_name in executives:
          c.send(b'F')
          c.close()
          return False
        c.send(b'T')
        c.close()
        lock.acquire()
        try:
          cache=set(executives)
          cache.remove(new_executive_name)
          executives=list(cache)
          with open('executives.json','w') as f:
            json.dump(executives,f)
          print(executives)
          lock.release()
        except:
          traceback.print_exc()
          lock.release()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='ban_account':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if ((name not in names) or (name in banned_accounts)) or (name not in admin):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send(b'T')
        banned_name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        banned_name=rsa.decrypt(stream_read_in(c,banned_name_len,step=4),private_key).decode()
        if (not banned_name in names) or (banned_name in admin) or (banned_name in executives):
          c.send(b'F')
          c.close()
          return False
        c.send(b'T')
        c.close()
        lock.acquire()
        try:
          cache=set(banned_accounts)
          cache.add(banned_name)
          banned_accounts=list(cache)
          with open('banned_accounts.json','w') as f:
            json.dump(banned_accounts,f)
          print(banned_accounts)
          lock.release()
        except:
          traceback.print_exc()
          lock.release()
      else:
        c.send('F'.encode())
        c.close()
    elif con=='unban_account':
      c.send(encoded_public_key_len)
      c.send(encoded_public_key)
      name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      name=rsa.decrypt(stream_read_in(c,name_len,step=4),private_key).decode()
      key_lenth=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
      key=rsa.decrypt(stream_read_in(c,key_lenth,step=4),private_key).decode()
      if ((name not in names) or (name in banned_accounts)) or (name not in admin):
        c.send(b'F')
        c.close()
        return False
      if passwords[name]==key:
        c.send(b'T')
        unbanned_name_len=struct.unpack("=L",stream_read_in(c,4,step=4))[0]
        unbanned_name=rsa.decrypt(stream_read_in(c,unbanned_name_len,step=4),private_key).decode()
        if (not unbanned_name in names) or (not unbanned_name in banned_accounts):
          c.send(b'F')
          c.close()
          return False
        c.send(b'T')
        c.close()
        lock.acquire()
        try:
          cache=set(banned_accounts)
          cache.remove(unbanned_name)
          banned_accounts=list(cache)
          with open('banned_accounts.json','w') as f:
            json.dump(banned_accounts,f)
          print(banned_accounts)
          lock.release()
        except:
          traceback.print_exc()
          lock.release()
      else:
        c.send('F'.encode())
        c.close()
    else:
      c.close()
  except Exception as e:
    print(e)
    traceback.print_exc()
    #
  c.close()
  print(addr,'over')

def client(s):
  while True:
    c,addr=s.accept()
    c.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,True)
    waiter=threading.Thread(target=handler,args=(c,addr))
    del c
    waiter.start()
    waiters.append(waiter)

def sever(s):
  while True:
    try:
      client(s)
    except Exception as e:
      traceback.print_exc()
      print(e)

admin=input('admin>>').split('|')

lock=None
lock = threading.Lock()
waiters=[]
public_key,private_key=rsa.newkeys(2048)
encoded_public_key=pickle.dumps(public_key)
encoded_public_key_len=struct.pack("=L",len(encoded_public_key))
chat_messages=[['system',"Hello_world!"],]
account_creatable=True
with open('names.json','r') as f:
  names=json.load(f)
with open('passwords.json','r') as f:
  passwords=json.load(f)
with open('community_bbs.json','r') as f:
  bbs=json.load(f)
with open('bbs_len.json','r') as f:
  bbs_end_code=json.load(f)
with open('executives.json','r') as f:
  executives=json.load(f)
with open('banned_accounts.json','r') as f:
  banned_accounts=json.load(f)
with open('account_creatable.json','r') as f:
  account_creatable=json.load(f)
def main():
  #chat_messages=[['system',"Hello_world!"],]
  #
  ipv6_address=input('IPv6_address:')
  if not ipv6_address=='':
    s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
    s.bind((ipv6_address,1024))
    s.listen(1000)
    s1=socket.socket()
    s1.bind(('127.0.0.1',2048))
    s1.listen(100)
    a=_thread.start_new_thread(sever,(s,))
    b=_thread.start_new_thread(sever,(s1,))
  else:
    s=socket.socket()
    s.bind((input('out_ipv4_address:'),3072))
    s.listen(1000)
    a=_thread.start_new_thread(sever,(s,))
  manager=_thread.start_new_thread(waiters_manager,())
  while True:pass
