import os
import base64
import datetime
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


parser = argparse.ArgumentParser(description='sumcrypt to secure images')
parser.add_argument('-m','--mode', help='Encryption or decryption mode')
parser.add_argument('-i','--input', help='Input dir image')
parser.add_argument('-k','--key', help='Enter your key')
parser.add_argument('-p','--password', help='Enter your password')
parser.add_argument('-s','--salt', help='Enter your salt')


args = parser.parse_args()


if args.mode == 'e':
	if args.input == 'all':
		files_count = 0
		start = datetime.datetime.now()
		for filename in os.listdir(os.getcwd()):
			if filename.endswith('png') or filename.endswith('jpg') or filename.endswith('jpeg') or filename.endswith('mp4'):
				with open(filename, "rb") as img_file:
					s = img_file.read()
					x = base64.b64encode(s)
					f = Fernet(args.key)
					encrypted = f.encrypt(x)
					output = f.encrypt(filename.encode())
					file = open(output.decode()+'.sc','wb')
					file.write(encrypted)
					file.close()
					files_count += 1
				os.remove(filename)
		time = datetime.datetime.now() - start
		print('Successfully encrypted ('+str(files_count)+') files, In: '+str(time.total_seconds())+' Seconds.')
	else:
		with open(args.input, "rb") as img_file:
			s = img_file.read()
			x = base64.b64encode(s)
			f = Fernet(args.key)
			encrypted = f.encrypt(x)
			output = f.encrypt(args.input.encode())
			file = open(output.decode()+'.sc','wb')
			file.write(encrypted)
			file.close()
			print('File encrypted successfully :' + output.decode())
		os.remove(args.input)
elif args.mode == 'd':
	if args.input == 'all':
		files_count = 0
		start = datetime.datetime.now()
		for filename in os.listdir(os.getcwd()):
			if filename.endswith('sc'):
				with open(filename, "rb") as dec:
					p = b''+dec.read()
					j = Fernet(args.key)
					decrypted = j.decrypt(p)
					output = j.decrypt(filename.encode())
					file = open(output,'wb')	
					file.write(base64.b64decode(decrypted))
					file.close()					
					files_count += 1
				os.remove(filename)
		time = datetime.datetime.now() - start
		print('Successfully decrypted ('+str(files_count)+') files, In :'+str(time.total_seconds())+' Seconds.')
	else:
		with open(args.input, "rb") as dec:
			p = b''+dec.read()
			j = Fernet(args.key)
			decrypted = j.decrypt(p)
			output = j.decrypt(args.input.encode())
			with open(output, "wb") as fh:
				fh.write(base64.b64decode(decrypted))
				print('File decrypted successfully : '+ output.decode())
		os.remove(args.input)
elif args.mode == 'k': 
	password = args.password.encode()
	salt = args.salt.encode()
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
		backend=default_backend()
		)
	key = base64.urlsafe_b64encode(kdf.derive(password))
	print(key.decode())
else:
	print("""Please use the following syntax : 
		pycrypt.py input output mode
		Example : pycrypt.py input.png output.txt e/d""")


