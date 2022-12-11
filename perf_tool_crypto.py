import filecmp
import os 
import time
import binascii
import csv
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import glob
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import timedelta
from pathlib import Path

#Global variable to keep record of time
time_collect = []

def createsmallfile(filename):
   '''Creates small file'''
   f = open(filename,"wb")
   f.seek(8000)
   f.write(b"\0")
   f.close()
   

def createmediumfile(filename):
   '''Creates large file'''
   f = open(filename,"wb")
   f.seek(1048576)
   f.write(b"\0")
   f.close()

def createlargefile(filename):
   '''Creates large file'''
   f = open(filename,"wb")
   f.seek(10485760)
   f.write(b"\0")
   f.close()

def comparefiles(file1,file2):
   '''Compares two files'''
   filecmp.clear_cache()
   if (filecmp.cmp(file1,file2,shallow=True)):
      print(f"The files {file1} and {file2} are verified!\n")

def generatekey(keysize):
   '''
   Generates keys 
   16 bytes = 128 bit key
   32 bytes = 256 bit key

   '''
   key = os.urandom(keysize)
   return key

def AES_CBC(key,inputFile,outputfile):
   '''Encrypts the file using AES_CBC mode'''

   # Opening the file and loading the original contents
   with open(inputFile, 'rb') as file:
      original = file.read()
      length = 16 - (len(original)%16)
      original += bytes([length])*length
      file.close()

   # Generating IV and encrypting the file contents
   iv = os.urandom(16)
   start_time = time.perf_counter_ns()
   cipher = Cipher(algorithms.AES(key),modes.CBC(iv))
   encryptor = cipher.encryptor()
   ct = encryptor.update(original) + encryptor.finalize()
   enc_time = get_time(start_time)
   time_collect.append(enc_time)
 
   # Writing the encrypted contents into the file
   with open(outputfile, 'wb') as file:   
      file.write(ct)
      file.close()
   print(f"The file {inputFile} has been encrypted and contents stored to {outputfile}")

   ## Opening the file and loading the encrypted contents
   with open(outputfile, 'rb') as file:
      encrypted = file.read()
      file.close()

   # Decrypting the file contents
   print('\nDecrypting file--------->')
   start_time = time.perf_counter_ns()
   decryptor = cipher.decryptor()
   pt = decryptor.update(encrypted) + decryptor.finalize()
   pt = pt[:-pt[-length]]
   dec_time = get_time(start_time) 
   time_collect.append(dec_time)

def TripleDES(key,inputFile,outputfile):
   '''Encrypts the file using AES_CBC mode'''

   # Opening the file and loading the original contents
   with open(inputFile, 'rb') as file:
      original = file.read()
      length = 16 - (len(original)%16)
      original += bytes([length])*length
      file.close()

   # Generating IV and encrypting the file contents
   iv = os.urandom(8)
   start_time = time.perf_counter_ns()
   cipher = Cipher(algorithms.TripleDES(key),modes.CBC(iv))
   encryptor = cipher.encryptor()
   ct = encryptor.update(original) + encryptor.finalize()
   enc_time = get_time(start_time)
   time_collect.append(enc_time)
 
   # Writing the encrypted contents into the file
   with open(outputfile, 'wb') as file:   
      file.write(ct)
      file.close()
   print(f"The file {inputFile} has been encrypted and contents stored to {outputfile}")

   # Opening the file and loading the encrypted contents
   with open(outputfile, 'rb') as file:
      encrypted = file.read()
      file.close()

   # Decrypting the file contents
   print('\nDecrypting file--------->')
   start_time = time.perf_counter_ns()
   decryptor = cipher.decryptor()
   pt = decryptor.update(encrypted) + decryptor.finalize()
   pt = pt[:-pt[-length]]
   dec_time = get_time(start_time) 
   time_collect.append(dec_time)
 
   # Writing the decrypted file contents into the file
   with open(outputfile,'wb') as file:
      file.write(pt)
      file.close()
   print(f"The file {outputfile} has been decrypted")


def AES_CTR(key,inputFile,outputfile):
   '''Encrypts the file using AES_CTR mode'''

   # Opening the file and loading the original contents
   with open(inputFile, 'rb') as file:
      original = file.read()
      file.close()

   # Generating IV and encrypting the file contents
   iv = os.urandom(16)
   start_time = time.perf_counter_ns()
   cipher = Cipher(algorithms.AES(key),modes.CTR(iv))
   encryptor = cipher.encryptor()
   ct = encryptor.update(original) + encryptor.finalize()
   enc_aes_ctr = get_time(start_time)
   time_collect.append(enc_aes_ctr)
 
   # Writing the encrypted contents into the file
   with open(outputfile, 'wb') as file:   
      file.write(ct)
      file.close()
   print(f"The file {inputFile} has been encrypted and contents stored to {outputfile}")

   # Opening the file and loading the encrypted contents
   with open(outputfile, 'rb') as file:
      encrypted = file.read()
      file.close()

   # Decrypting the file contents
   print('\nDecrypting file--------->')
   start_time = time.perf_counter_ns()
   decryptor = cipher.decryptor()
   pt = decryptor.update(encrypted) + decryptor.finalize()
   dec_aes_ctr = get_time(start_time)
   time_collect.append(dec_aes_ctr)
 
   # Writing the decrypted file contents into the file
   with open(outputfile,'wb') as file:
      file.write(pt)
      file.close()
   print(f"The file {outputfile} has been decrypted")


def RSA_chunking(inputfile,outputfile,keysize):
   '''Encrypts the file using RSA 2048 bit key [with chunking]'''

   # Generating private and public key
   print(f'Generating {keysize} bit key--------->')
   start_time = time.perf_counter_ns() 
   private_key = rsa.generate_private_key(public_exponent=65537,key_size=keysize)
   public_key = private_key.public_key()
   key_time = get_time(start_time)
   time_collect.append(key_time)


   if(keysize == 2048):
      encryption_blocksize = 190 # 66 bytes less from the original key size due to padding (it breaks beyond this!)
      decryption_blocksize = 256

   if(keysize == 3072):
      encryption_blocksize = 318 # 66 bytes less from the original key size due to padding (it breaks beyond this!)
      decryption_blocksize = 384

   # Calling chunking and encrypting the chunks
   print('\nEncrypting file--------->')
   start_time = time.perf_counter_ns() 
   ciphertext= bytes()
   for block in chunking(inputfile, encryption_blocksize):
      # print(len(block))
      cipherblock = public_key.encrypt(
         block,
         padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
         )
      )
      # Storing all cipherblocks
      ciphertext += cipherblock
   enc_rsa = get_time(start_time)
   time_collect.append(enc_rsa)

   with open(outputfile, 'wb') as file:   
      file.write(ciphertext)
      file.close()
   print(f"The file {inputfile} has been encrypted and contents stored to {outputfile}")
   
   # Decrypting the ciphertext using private key to be writtten to output file
   print('\nDecrypting file--------->')
   start_time = time.perf_counter_ns() 
   plain_text = bytes()
   for ctblock in chunked(ciphertext,decryption_blocksize):
      plain_block = private_key.decrypt(
         ctblock,
         padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
         )
      )
      plain_text += plain_block
   dec_rsa = get_time(start_time)
   time_collect.append(dec_rsa)

   # Writing the decrypted file contents into the file
   with open(outputfile,'wb') as file:
      file.write(plain_text)
      file.close()
   print(f"The file {outputfile} has been decrypted")
   



def chunking(file_name, size):
   with open(file_name,'rb') as file:
      while True:
         data = file.read(size)
         if not data:
            break
         yield data
   file.close()

def chunked(source,size):
   for i in range(0,len(source),size):
      yield source[i:i+size]   


def SHA_256_SHA_512_SHA3_256 (inputfile):
   '''Generates SHA-256, SHA-512 and SHA3-256 hashes of the file'''

   # Opening the file and loading the original contents
   with open(inputfile, 'rb') as file:
      original = file.read()
      file.close()

   start_time = time.perf_counter_ns() 
   digest = hashes.Hash(hashes.SHA256())
   digest.update(original)
   print(f'\nThe generated SHA-256 hash is : {binascii.hexlify(digest.finalize())}')
   sha_256 = get_time(start_time)
   time_collect.append(sha_256)

   start_time = time.perf_counter_ns() 
   digest = hashes.Hash(hashes.SHA512())
   digest.update(original)
   print(f'\nThe generated SHA-512 hash is : {binascii.hexlify(digest.finalize())}')
   sha_512 = get_time(start_time)
   sha_512 = get_time(start_time)
   time_collect.append(sha_512)

   start_time = time.perf_counter_ns() 
   digest = hashes.Hash(hashes.SHA3_256())
   digest.update(original)
   print(f'\nThe generated SHA3-256 hash is : {binascii.hexlify(digest.finalize())}')
   sha3_256 = get_time(start_time)
   sha3_256 = get_time(start_time)
   time_collect.append(sha3_256)

def DSA(inputfile, keysize):
   '''Signs the files using the key and verifies the corresponding signatures'''
   
   print(f'Generating {keysize} bit key--------->')
   start_time = time.perf_counter_ns() 
   private_key = dsa.generate_private_key(key_size=keysize, )
   public_key = private_key.public_key()
   key_time = get_time(start_time)
   time_collect.append(key_time)
   

   with open(inputfile, 'rb') as file:
      original = file.read()
      file.close()

   print(f'\nGenerating signature--------->')
   start_time = time.perf_counter_ns() 
   signature = private_key.sign(original,hashes.SHA256())
   print(f'The signature is - {binascii.hexlify(signature)}')
   sig_gen_dsa = get_time(start_time)
   time_collect.append(sig_gen_dsa)

   print(f'\nVerifying signature--------->')
   start_time = time.perf_counter_ns()
   if public_key.verify(signature,original,hashes.SHA256()) == None:
      print('Signature Verified!')
   sig_verify_dsa = get_time(start_time)
   time_collect.append(sig_verify_dsa)


def get_time(start_time):
   nano_second = time.perf_counter_ns() - start_time
   micro_second = nano_second/1000
   seconds = str(timedelta(microseconds=micro_second))
   seconds_only = micro_second/1000000
   print(f'Time taken = {nano_second} nano seconds = {micro_second} Micro seconds = {seconds} Seconds')
   return seconds_only

def create_result_csv(csv_filepath): 
   os.makedirs(os.path.dirname(csv_filepath), exist_ok=True)
   with open(csv_filepath,"w",newline="") as f:
      writer = csv.writer(f)
      writer.writerow(["Algorithms","Time Key","Time Encrption", "Time Decryption"])
      f.close()

def create_result_sha_csv(csv_filepath): 
   os.makedirs(os.path.dirname(csv_filepath), exist_ok=True)
   with open(csv_filepath,"w",newline="") as f:
      writer = csv.writer(f)
      writer.writerow(["SHA","SHA_256","SHA_512", "SHA3_256"])
      f.close()

def collect_time_to_csv(csv_filepath,time_collection):
   with open(csv_filepath,"a",newline="") as f:
         writer = csv.writer(f)
         writer.writerow(time_collection)
         f.close()

def reset_list(entry,key_used):
   time_collect.clear()
   time_collect.append(entry)
   time_collect.append(key_used)

def Run_AES_CBC(input_small,output_small,input_large,output_large,res_file):
   time_collect.clear()
   time_collect.append("AES_CBC_Small_File")

   print('----------------Starting AES_CBC------------------')
   print('Generating 128 bit key--------->')
   start_time = time.perf_counter_ns()
   key = generatekey(16) #16 bytes key = 128 bits key
   key_time = get_time(start_time)
   print(f'The key is : {binascii.hexlify(key)}') #string is prefixed with the ‘b,’ which says that it produces byte data type instead of the string data type
   time_collect.append(key_time)
   
   print('\nEncrypting 1KB file using AES CBC--------->')
   AES_CBC(key,input_small,output_small)
   print('Verifying files--------->')
   comparefiles(input_small,output_small)
   collect_time_to_csv(res_file,time_collect)
   
   reset_list("AES_CBC_Large_File",key_time)

   print('\nEncrypting 10MB file using AES CBC--------->')
   AES_CBC(key,input_large,output_large)
   print('Verifying files--------->')
   comparefiles(input_large,output_large)

   collect_time_to_csv(res_file,time_collect)

def Run_Triple_DES(input_small,output_small,input_large,output_large,res_file):
   time_collect.clear()
   time_collect.append("TripleDES_Small_File")
   print('----------------Starting TripleDES------------------')
   print('Generating 128 bit key--------->')
   start_time = time.perf_counter_ns()
   key = generatekey(16) #16 bytes key = 128 bits key
   key_time = get_time(start_time)
   print(f'The key is : {binascii.hexlify(key)}') #string is prefixed with the ‘b,’ which says that it produces byte data type instead of the string data type
   time_collect.append(key_time)
   
   print('\nEncrypting 1KB file using AES CBC--------->')
   TripleDES(key,input_small,output_small)
   print('Verifying files--------->')
   comparefiles(input_small,output_small)
   collect_time_to_csv(res_file,time_collect)
   
   reset_list("TripleDES_Large_File",key_time)

   print('\nEncrypting 10MB file using AES CBC--------->')
   TripleDES(key,input_large,output_large)
   print('Verifying files--------->')
   comparefiles(input_large,output_large)

   collect_time_to_csv(res_file,time_collect)

def Run_AES_CTR(input_small,output_small,input_large,output_large,res_file):

   time_collect.clear()
   time_collect.append("AES_CTR_Small_File")

   print('----------------Starting AES_CTR------------------')
   print('Generating 128 bit key--------->')
   start_time = time.perf_counter_ns()
   key = generatekey(16) #16 bytes key = 128 bits key
   key_time = get_time(start_time)
   time_collect.append(key_time)
   print(f'The key is : {binascii.hexlify(key)}') #string is prefixed with the ‘b,’ which says that it produces byte data type instead of the string data type

   
   print('\nEncrypting 1KB file using AES CTR--------->')
   AES_CTR(key,input_small,output_small)
   print('Verifying files--------->')
   comparefiles(input_small,output_small)
   collect_time_to_csv(res_file,time_collect)

   # reset our collection for new row entry
   reset_list("AES_CTR_Large_File",key_time)

   print('\nEncrypting 10MB file using AES CTR--------->')
   AES_CTR(key,input_large,output_large)
   print('Verifying files--------->')
   comparefiles(input_large,output_large)
   collect_time_to_csv(res_file,time_collect)

def Run_AES_CTR_256(input_small,output_small,input_large,output_large,res_file):
 
   time_collect.clear()
   time_collect.append("AES_CTR_256_Small_File")

   print('----------------Starting AES_CTR_256------------------')
   print('Generating 256 bit key--------->')
   start_time = time.perf_counter_ns()
   key = generatekey(32) #32 bytes key = 256 bits key
   key_time = get_time(start_time)
   time_collect.append(key_time)
   print(f'The key is : {binascii.hexlify(key)}') #string is prefixed with the ‘b,’ which says that it produces byte data type instead of the string data type


   print('\nEncrypting 1KB file using AES CTR--------->')
   AES_CTR(key,input_small,output_small)
   print('Verifying files--------->')
   comparefiles(input_small,output_small)
   collect_time_to_csv(res_file,time_collect)

   # reset our collection for new row entry
   reset_list("AES_CTR_256_Large_File",key_time)

   print('\nEncrypting 10MB file using AES CTR--------->')
   AES_CTR(key,input_large,output_large)
   print('Verifying files--------->')
   comparefiles(input_large,output_large)
   collect_time_to_csv(res_file,time_collect)

def Run_RSA_2048(input_small,output_small,input_large,output_large,res_file):

   time_collect.clear()
   time_collect.append("RSA_2048_Small_File")

   print('----------------Starting RSA 2048------------------')
   print('\nEncrypting 1KB file using RSA 2048 bit key--------->')
   RSA_chunking(input_small,output_small, 2048)
   print('Verifying files--------->')
   comparefiles(input_small,output_small)
   collect_time_to_csv(res_file,time_collect)
   
   # reset our collection for new row entry
   time_collect.clear()
   time_collect.append("RSA_2048_Large_File")

   print('\nEncrypting 1MB file using RSA 2048 bit key--------->')
   RSA_chunking(input_large,output_large, 2048)
   print('Verifying files--------->')
   comparefiles(input_large,output_large)
   collect_time_to_csv(res_file,time_collect)

def Run_RSA_3072(input_small,output_small,input_large,output_large,res_file):

   time_collect.clear()
   time_collect.append("RSA_3072_Small_File")

   print('----------------Starting RSA 3072------------------')
   print('\nEncrypting 1KB file using RSA 3072 bit key--------->')
   RSA_chunking(input_small,output_small, 3072)
   print('Verifying files--------->')
   comparefiles(input_small,output_small)
   collect_time_to_csv(res_file,time_collect)

   # reset our collection for new row entry
   time_collect.clear()
   time_collect.append("RSA_3072_Large_File")
   
   print('\nEncrypting 1MB file using RSA 3072 bit key--------->')
   RSA_chunking(input_large,output_large, 3072)
   print('Verifying files--------->')
   comparefiles(input_large,output_large)
   collect_time_to_csv(res_file,time_collect)

def Run_SHA(input_small,input_large,res_file,file_type):

   time_collect.clear()
   time_collect.append(file_type+"Small_File")

   print('----------------Staring SHA------------------')
   print('\nGenerating hashes for 1KB file--------->')
   SHA_256_SHA_512_SHA3_256(input_small)
   collect_time_to_csv(res_file,time_collect)
   
   time_collect.clear()
   time_collect.append(file_type+"Large_File")

   print('\nGenerating hashes for 10MB file--------->')
   SHA_256_SHA_512_SHA3_256(input_large)
   collect_time_to_csv(res_file,time_collect)

def Run_DSA_2048(input_small,input_large,res_file):
   time_collect.clear()
   time_collect.append("DSA_2048_Small_File")

   print('\n----------------Starting DSA 2048------------------')
   print('\nSigning 1KB file using DSA 2048 bit key--------->')
   DSA(input_small,2048)
   collect_time_to_csv(res_file,time_collect)

   # reset our collection for new row entry
   time_collect.clear()
   time_collect.append("DSA_2048_Large_File")

   print('\nSigning 10MB file using DSA 2048 bit key--------->')
   DSA(input_large,2048)
   collect_time_to_csv(res_file,time_collect)

def Run_DSA_3072(input_small,input_large,res_file):
   time_collect.clear()
   time_collect.append("DSA_3072_Small_File")

   print('\n----------------Starting DSA 3072------------------')
   print('\nSigning 1KB file using DSA 3072 bit key--------->')
   DSA(input_small,3072)
   collect_time_to_csv(res_file,time_collect)

   # reset our collection for new row entry
   time_collect.clear()
   time_collect.append("DSA_3072_Large_File")

   print('\nSigning 10MB file using DSA 3072 bit key--------->')
   DSA(input_large,3072)
   collect_time_to_csv(res_file,time_collect)

def Plot_Graph(data,label):
   # Initialize the lists for X and Y
   data = pd.read_csv(data)

   df = pd.DataFrame(data)
   algos = df['Algorithms']

   y = np.arange(len(algos))
   h = 0.3
   plt.barh(y-h, df['Time Key'].values, height=h, label='Key')
   plt.barh(y, df['Time Encrption'].values, height=h, label='Encrption')
   plt.barh(y+h, df['Time Decryption'].values, height=h, label='Decryption')
   
   # Plot the data using bar() method
   plt.yticks(y, algos)
   plt.tight_layout()
   plt.xlabel(label)
   plt.ylabel('Seconds')
   plt.legend(loc='upper right', fancybox=True, ncol=5)

   # Show the plot
   plt.show()

def Plot_Graph_SHA(data,label):
   # Initialize the lists for X and Y
   data = pd.read_csv(data)

   df = pd.DataFrame(data)
   algos = df['SHA']

   y = np.arange(len(algos))
   h = 0.3
   plt.barh(y-h, df['SHA_256'].values, height=h, label='SHA_256')
   plt.barh(y, df['SHA_512'].values, height=h, label='SHA_512')
   plt.barh(y+h, df['SHA3_256'].values, height=h, label='SHA3_256')
   
   # Plot the data using bar() method
   plt.yticks(y, algos)
   plt.tight_layout()
   plt.xlabel(label)
   plt.ylabel('Seconds')
   plt.legend(loc='upper right',  fancybox=True, ncol=5)
   
   # Show the plot
   plt.show()

def Generate_Report(path):
   files = Path(path).glob('*.csv') 
   dataframes = list()
   for f in files:
      data = pd.read_csv(f)
      data['file'] = f.stem
      dataframes.append(data)

   df = pd.concat(dataframes, ignore_index=True)
   df.to_html("Report.htm")

if __name__=='__main__':

   #Initialize paths for our data files
   smalltxtfile,smalltxtfile_after = 'Data\\Small\\smalltxtfile.txt','Data\\Small\\smalltxtfile_after.txt'
   mediumtxtfile,mediumtxtfile_after = 'Data\\Medium\\mediumtxtfile.txt','Data\\Medium\\mediumtxtfile_after.txt'
   largetxtfile,largetxtfile_after = 'Data\\Large\\largetxtfile.txt','Data\\Large\\largetxtfile_after.txt'

   smallimagefile,smallimagefile_after = 'Data\\Small\\smalljpg.jpg','Data\\Small\\smalljpg_after.jpg'
   mediumimagefile,mediumimagefile_after = 'Data\\Medium\\mediumjpg.jpg','Data\\Medium\\mediumjpg_after.jpg'
   largeimagefile,largeimagefile_after = 'Data\\Large\\largejpg.jpg','Data\\Large\\largejpg_after.jpg'
   
   smallcsvfile,smallcsvfile_after = 'Data\\Small\\smallcsv.csv','Data\\Small\\smallcsv_after.csv'
   mediumcsvfile,mediumcsvfile_after = 'Data\\Medium\\mediumcsv.csv','Data\\Medium\\mediumcsv_after.csv'
   largecsvfile,largecsvfile_after = 'Data\\Large\\largecsv.csv','Data\\Large\\largecsv_after.csv'

   smallgiffile,smallgiffile_after = 'Data\\Small\\smallgif.gif','Data\\Small\\smallgif_after.gif'
   mediumgiffile,mediumgiffile_after = 'Data\\Medium\\mediumgif.gif','Data\\Medium\\mediumgif_after.gif'
   largegiffile,largegiffile_after = 'Data\\Large\\largegif.gif','Data\\Large\\largegif_after.gif'

   smallmp3file,smallmp3file_after = 'Data\\Small\\smallmp3.mp3','Data\\Small\\smallmp3_after.mp3'
   mediummp3file,mediummp3file_after = 'Data\\Medium\\mediummp3.mp3','Data\\Medium\\mediummp3_after.mp3'
   largemp3file,largemp3file_after = 'Data\\Large\\largemp3.mp3','Data\\Large\\largemp3_after.mp3'

   smallmp4file,smallmp4file_after = 'Data\\Small\\smallmp4.mp4','Data\\Small\\smallmp4_after.mp4'
   mediummp4file,mediummp4file_after = 'Data\\Medium\\mediummp4.mp4','Data\\Medium\\mediummp4_after.mp4'
   largemp4file,largemp4file_after = 'Data\\Large\\largemp4.mp4','Data\\Large\\largemp4_after.mp4'

   smallpdffile,smallpdffile_after = 'Data\\Small\\smallpdf.pdf','Data\\Small\\smallpdf_after.pdf'
   mediumpdffile,mediumpdffile_after = 'Data\\Medium\\mediumpdf.pdf','Data\\Medium\\mediumpdf_after.pdf'
   largepdffile,largepdffile_after = 'Data\\Large\\largepdf.pdf','Data\\Large\\largepdf_after.pdf'

   smallzipfile,smallzipfile_after = 'Data\\Small\\smallzip.zip','Data\\Small\\smallzip_after.zip'
   mediumzipfile,mediumzipfile_after = 'Data\\Medium\\mediumzip.zip','Data\\Medium\\mediumzip_after.zip'
   largezipfile,largezipfile_after = 'Data\\Large\\largezip.zip','Data\\Large\\largezip_after.zip'   

   text_res_file = 'Results\\text_results.csv'
   gif_res_file = 'Results\\gif_results.csv'
   csv_res_file = 'Results\\csv_results.csv'
   image_res_file = 'Results\\image_results.csv'
   mp3_res_file = 'Results\\mp3_results.csv'
   mp4_res_file = 'Results\\mp4_results.csv'
   pdf_res_file = 'Results\\pdf_results.csv'
   zip_res_file = 'Results\\zip_results.csv'
   sha_res_file = 'Results\\sha_results.csv'

   path= r'Results'

   createsmallfile(smalltxtfile)
   createmediumfile(mediumtxtfile)
   createlargefile(largetxtfile)
   create_result_csv(text_res_file)
   create_result_csv(gif_res_file)
   create_result_csv(csv_res_file)
   create_result_csv(image_res_file)
   create_result_csv(mp3_res_file)
   create_result_csv(mp4_res_file)
   create_result_csv(pdf_res_file)
   create_result_csv(zip_res_file)
   create_result_sha_csv(sha_res_file)
   


   ##################################### TEXT ####################################################################
   
   #region AES_CBC

   Run_AES_CBC(smalltxtfile,smalltxtfile_after,largetxtfile,largetxtfile_after,text_res_file)
   
   #endregion

   #region AES_CTR

   Run_AES_CTR(smalltxtfile,smalltxtfile_after,largetxtfile,largetxtfile_after,text_res_file)

   #endregion

   #region AES_CTR_256

   Run_AES_CTR_256(smalltxtfile,smalltxtfile_after,largetxtfile,largetxtfile_after,text_res_file)
   
   #endregion

   #region TripleDES

   Run_Triple_DES(smalltxtfile,smalltxtfile_after,largetxtfile,largetxtfile_after,text_res_file)
   
   #endregion

   #region RSA_2048
   
   Run_RSA_2048(smalltxtfile,smalltxtfile_after,mediumtxtfile,mediumtxtfile_after,text_res_file)

   #endregion
   
   #region RSA_3072

   Run_RSA_3072(smalltxtfile,smalltxtfile_after,mediumtxtfile,mediumtxtfile_after,text_res_file)

   #endregion

   #region SHA

   Run_SHA(smalltxtfile,largetxtfile,sha_res_file,"Text_")

   #endregion

   #region DSA_2048

   Run_DSA_2048(smalltxtfile,largetxtfile,text_res_file)
 
   #endregion

   #region DSA_3072

   Run_DSA_2048(smalltxtfile,largetxtfile,text_res_file)

   #endregion

   ################################# GIF ##########################################
   #region AES_CBC

   Run_AES_CBC(smallgiffile,smallgiffile_after,largegiffile,largegiffile_after,gif_res_file)
   
   #endregion

   #region AES_CTR

   Run_AES_CTR(smallgiffile,smallgiffile_after,largegiffile,largegiffile_after,gif_res_file)

   #endregion

   #region AES_CTR_256

   Run_AES_CTR_256(smallgiffile,smallgiffile_after,largegiffile,largegiffile_after,gif_res_file)
   
   #endregion

   #region TripleDES

   Run_Triple_DES(smallgiffile,smallgiffile_after,largegiffile,largegiffile_after,gif_res_file)
   
   #endregion

   #region RSA_2048
   
   Run_RSA_2048(smallgiffile,smallgiffile_after,mediumgiffile,mediumgiffile_after,gif_res_file)

   #endregion
   
   #region RSA_3072

   Run_RSA_3072(smallgiffile,smallgiffile_after,mediumgiffile,mediumgiffile_after,gif_res_file)

   #endregion

   #region SHA

   Run_SHA(smallgiffile,largegiffile,sha_res_file,"Gif_")

   #endregion

   #region DSA_2048

   Run_DSA_2048(smallgiffile,largegiffile,gif_res_file)
 
   #endregion

   #region DSA_3072

   Run_DSA_3072(smallgiffile,largegiffile,gif_res_file)
   
   #endregion

######################################## CSV ###########################################
   #region AES_CBC

   Run_AES_CBC(smallcsvfile,smallcsvfile_after,largecsvfile,largecsvfile_after,csv_res_file)
   
   #endregion

   #region AES_CTR

   Run_AES_CTR(smallcsvfile,smallcsvfile_after,largecsvfile,largecsvfile_after,csv_res_file)

   #endregion

   #region AES_CTR_256

   Run_AES_CTR_256(smallcsvfile,smallcsvfile_after,largecsvfile,largecsvfile_after,csv_res_file)
   
   #endregion

   #region TripleDES

   Run_Triple_DES(smallcsvfile,smallcsvfile_after,largecsvfile,largecsvfile_after,csv_res_file)
   
   #endregion

   #region RSA_2048
   
   Run_RSA_2048(smallcsvfile,smallcsvfile_after,mediumcsvfile,mediumcsvfile_after,csv_res_file)

   #endregion
   
   #region RSA_3072

   Run_RSA_3072(smallcsvfile,smallcsvfile_after,mediumcsvfile,mediumcsvfile_after,csv_res_file)

   #endregion

   #region SHA

   Run_SHA(smallcsvfile,largecsvfile,sha_res_file,"Csv_")

   #endregion

   #region DSA_2048

   Run_DSA_2048(smallcsvfile,largecsvfile,csv_res_file)
 
   #endregion

   #region DSA_3072

   Run_DSA_3072(smallcsvfile,largecsvfile,csv_res_file)
   
   #endregion

######################################## JPG ###########################################
   #region AES_CBC

   Run_AES_CBC(smallimagefile,smallimagefile_after,largeimagefile,largeimagefile_after,image_res_file)
   
   #endregion

   #region AES_CTR

   Run_AES_CTR(smallimagefile,smallimagefile_after,largeimagefile,largeimagefile_after,image_res_file)

   #endregion

   #region AES_CTR_256

   Run_AES_CTR_256(smallimagefile,smallimagefile_after,largeimagefile,largeimagefile_after,image_res_file)
   
   #endregion

   #region TripleDES

   Run_Triple_DES(smallimagefile,smallimagefile_after,largeimagefile,largeimagefile_after,image_res_file)
   
   #endregion

   #region RSA_2048
   
   Run_RSA_2048(smallimagefile,smallimagefile_after,mediumimagefile,mediumimagefile_after,image_res_file)

   #endregion
   
   #region RSA_3072

   Run_RSA_3072(smallimagefile,smallimagefile_after,mediumimagefile,mediumimagefile_after,image_res_file)

   #endregion

   #region SHA

   Run_SHA(smallimagefile,largeimagefile,sha_res_file,"Jpg_")

   #endregion

   #region DSA_2048

   Run_DSA_2048(smallimagefile,largeimagefile,image_res_file)
 
   #endregion

   #region DSA_3072

   Run_DSA_3072(smallimagefile,largeimagefile,image_res_file)
   
   #endregion

######################################## MP3 ###########################################
   #region AES_CBC

   Run_AES_CBC(smallmp3file,smallmp3file_after,largemp3file,largemp3file_after,mp3_res_file)
   
   #endregion

   #region AES_CTR

   Run_AES_CTR(smallmp3file,smallmp3file_after,largemp3file,largemp3file_after,mp3_res_file)

   #endregion

   #region AES_CTR_256

   Run_AES_CTR_256(smallmp3file,smallmp3file_after,largemp3file,largemp3file_after,mp3_res_file)
   
   #endregion

   #region TripleDES

   Run_Triple_DES(smallmp3file,smallmp3file_after,largemp3file,largemp3file_after,mp3_res_file)
   
   #endregion

   #region RSA_2048
   
   Run_RSA_2048(smallmp3file,smallmp3file_after,mediummp3file,mediummp3file_after,mp3_res_file)

   #endregion
   
   #region RSA_3072

   Run_RSA_3072(smallmp3file,smallmp3file_after,mediummp3file,mediummp3file_after,mp3_res_file)

   #endregion

   #region SHA

   Run_SHA(smallmp3file,largemp3file,sha_res_file,"Mp3_")

   #endregion

   #region DSA_2048

   Run_DSA_2048(smallmp3file,largemp3file,mp3_res_file)
 
   #endregion

   #region DSA_3072

   Run_DSA_3072(smallmp3file,largemp3file,mp3_res_file)
   
   #endregion

   ######################################## MP4 ###########################################
   #region AES_CBC

   Run_AES_CBC(smallmp4file,smallmp4file_after,largemp4file,largemp4file_after,mp4_res_file)
   
   #endregion

   #region AES_CTR

   Run_AES_CTR(smallmp4file,smallmp4file_after,largemp4file,largemp4file_after,mp4_res_file)

   #endregion

   #region AES_CTR_256

   Run_AES_CTR_256(smallmp4file,smallmp4file_after,largemp4file,largemp4file_after,mp4_res_file)
   
   #endregion

   #region TripleDES

   Run_Triple_DES(smallmp4file,smallmp4file_after,largemp4file,largemp4file_after,mp4_res_file)
   
   #endregion

   #region RSA_2048
   
   Run_RSA_2048(smallmp4file,smallmp4file_after,mediummp4file,mediummp4file_after,mp4_res_file)

   #endregion
   
   #region RSA_3072

   Run_RSA_3072(smallmp4file,smallmp4file_after,mediummp4file,mediummp4file_after,mp4_res_file)

   #endregion

   #region SHA

   Run_SHA(smallmp4file,largemp4file,sha_res_file,"Mp4_")

   #endregion

   #region DSA_2048

   Run_DSA_2048(smallmp4file,largemp4file,mp4_res_file)
 
   #endregion

   #region DSA_3072

   Run_DSA_3072(smallmp4file,largemp4file,mp4_res_file)
   
   #endregion

   ######################################## PDF ###########################################
   #region AES_CBC

   Run_AES_CBC(smallpdffile,smallpdffile_after,largepdffile,largepdffile_after,pdf_res_file)
   
   #endregion

   #region AES_CTR

   Run_AES_CTR(smallpdffile,smallpdffile_after,largepdffile,largepdffile_after,pdf_res_file)

   #endregion

   #region AES_CTR_256

   Run_AES_CTR_256(smallpdffile,smallpdffile_after,largepdffile,largepdffile_after,pdf_res_file)
   
   #endregion

   #region TripleDES

   Run_Triple_DES(smallpdffile,smallpdffile_after,largepdffile,largepdffile_after,pdf_res_file)
   
   #endregion

   #region RSA_2048
   
   Run_RSA_2048(smallpdffile,smallpdffile_after,mediumpdffile,mediumpdffile_after,pdf_res_file)

   #endregion
   
   #region RSA_3072

   Run_RSA_3072(smallpdffile,smallpdffile_after,mediumpdffile,mediumpdffile_after,pdf_res_file)

   #endregion

   #region SHA

   Run_SHA(smallpdffile,largepdffile,sha_res_file,"Pdf_")

   #endregion

   #region DSA_2048

   Run_DSA_2048(smallpdffile,largepdffile,pdf_res_file)
 
   #endregion

   #region DSA_3072

   Run_DSA_3072(smallpdffile,largepdffile,pdf_res_file)
   
   #endregion

   ######################################## ZIP ###########################################
   #region AES_CBC

   Run_AES_CBC(smallzipfile,smallzipfile_after,largezipfile,largezipfile_after,zip_res_file)
   
   #endregion

   #region AES_CTR

   Run_AES_CTR(smallzipfile,smallzipfile_after,largezipfile,largezipfile_after,zip_res_file)

   #endregion

   #region AES_CTR_256

   Run_AES_CTR_256(smallzipfile,smallzipfile_after,largezipfile,largezipfile_after,zip_res_file)
   
   #endregion

   #region TripleDES

   Run_Triple_DES(smallzipfile,smallzipfile_after,largezipfile,largezipfile_after,zip_res_file)
   
   #endregion

   #region RSA_2048
   
   Run_RSA_2048(smallzipfile,smallzipfile_after,mediumzipfile,mediumzipfile_after,zip_res_file)

   #endregion
   
   #region RSA_3072

   Run_RSA_3072(smallzipfile,smallzipfile_after,mediumzipfile,mediumzipfile_after,zip_res_file)

   #endregion

   #region SHA

   Run_SHA(smallzipfile,largezipfile,sha_res_file,"Zip_")

   #endregion

   #region DSA_2048

   Run_DSA_2048(smallzipfile,largezipfile,zip_res_file)
 
   #endregion

   #region DSA_3072

   Run_DSA_3072(smallpdffile,largepdffile,pdf_res_file)
   
   #endregion

   ########################## Generating Reports ########################

   Generate_Report(path)

   ###################### Plot Graphs ##########################
   Plot_Graph(text_res_file,'Text Files')
   Plot_Graph(csv_res_file,'CSV Files')
   Plot_Graph(gif_res_file,'GIF Files')
   Plot_Graph(image_res_file,'JPG Files')
   Plot_Graph(mp3_res_file,'MP3 Files')
   Plot_Graph(mp4_res_file,'MP4 Files')
   Plot_Graph(pdf_res_file,'PDF Files')
   Plot_Graph(zip_res_file,'ZIP Files')
   Plot_Graph_SHA(sha_res_file,'SHA Comparision')
