## Python code to Huffman code an image, Encrypt with Fernet and RSA and decrypt/decode
# to reconstruct original image
## Info Theory and Coding assignment
## Group number 39
## Tejas, Shiven and Yashas

import heapq
import os
import numpy as np
from imageio import imread 
import cryptography
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from bitstring import BitArray
from timeit import default_timer

# HeapNode class for creating intensity probability min heap
class HeapNode:
	def __init__(self, value, freq):
		self.value = value
		self.freq = freq
		self.left = None
		self.right = None
	def __lt__(self, other):
		return self.freq < other.freq
	def __eq__(self, other):
		if(other == None):
			return False
		if(not isinstance(other, HeapNode)):
			return False
		return self.freq == other.freq


# Huffman coding class
class HuffmanCoding:
	def __init__(self):
		self.heap = []
		self.codes = {}
		self.reverse_mapping = {}

	## Functions for compression:

	# Makes dictionary of frequencies for min heap
	def make_frequency_dict(self, arr):
		frequency = {}
		for value in arr:
			if not value in frequency:
				frequency[value] = 0
			frequency[value] += 1
		return frequency

	# Creates min heap using frequency dictionary
	def make_heap(self, frequency):
		for key in frequency:
			node = HeapNode(key, frequency[key])
			heapq.heappush(self.heap, node)

	# Function to merge two minimum probability nodes
	def merge_nodes(self):
		while(len(self.heap)>1):
			node1 = heapq.heappop(self.heap)
			node2 = heapq.heappop(self.heap)

			merged = HeapNode(None, node1.freq + node2.freq)
			merged.left = node1
			merged.right = node2

			heapq.heappush(self.heap, merged)

	# Recursive function to calculate codes for each intensity
	def make_codes_helper(self, root, current_code):
		if(root == None):
			return

		if(root.value != None):
			self.codes[root.value] = current_code
			self.reverse_mapping[current_code] = root.value
			return

		self.make_codes_helper(root.left, current_code + "0")
		self.make_codes_helper(root.right, current_code + "1")

	# Intializes codes and calls the above helper
	def make_codes(self):
		root = heapq.heappop(self.heap)
		current_code = ""
		self.make_codes_helper(root, current_code)

	# Encodes given array using codes
	def encode_arr(self, arr):
		encoded_text = ""
		for value in arr:
			encoded_text += self.codes[value]
		return encoded_text

	# Writes codes to file 
	def write_codes(self):
		file_codes = open(r"codes.txt", "w")
		for value in self.codes:
			write_str = str(value)
			for i in range(4 - len(write_str)):
				write_str += " "
			write_str += " : "
			write_str += str(self.codes[value])
			write_str += '\n'
			file_codes.write(write_str)
		file_codes.close()

	# Helper function to perform end to end compression given array
	def compress(self, a):
		frequency = self.make_frequency_dict(a)
		self.make_heap(frequency)
		self.merge_nodes()
		self.make_codes()
		self.write_codes()

		encoded_text = self.encode_arr(a)
		print("Compressed")
		return encoded_text


	## Functions for decompression

	# Decodes encoded values using reverse mapping
	def decode_arr(self, encoded):
		current_code = ""
		decoded = []

		for bit in encoded:
			current_code += bit
			if(current_code in self.reverse_mapping):
				value = self.reverse_mapping[current_code]
				decoded.append(value)
				current_code = ""

		return decoded

	# Helper function for decompression
	def decompress(self, encoded):
		decompressed = self.decode_arr(encoded)
		print("Decompressed")
		return decompressed


# Read image and store in img
filepath = 'simple sample.bmp'
img = imread(filepath)
print("File : " , filepath)
shape = img.shape

# Flatten image to array 
a = img.flatten()

# Create huffman coding object to access functions
h = HuffmanCoding()

#Compress and pad to write to file
start_comp = default_timer()
compressed = h.compress(a)
str_pad = 8 - (len(compressed) % 8)
end_comp = default_timer()
print("Compression time = ", (end_comp - start_comp) * 1000)

file1 = open(r"unencrypted_compressed_data.txt", "wb")
file1.write(int(compressed, 2).to_bytes((len(compressed) + 7)//8, 'big'))
file1.close()

# Calculate compression ratio, 8 is used because intensity values are 8 bit
compression_ratio = (1 - len(compressed)/(8 * len(a))) * 100
print("Compression is" ,compression_ratio, "percent")
string_bytes = int(compressed, 2).to_bytes((len(compressed) + 7)//8, 'big')

# Generate Fernet key and encrypt data using it
key= Fernet.generate_key()
fernet_e = Fernet(key)
start_m_enc = default_timer()
encrypted_bytes = fernet_e.encrypt(string_bytes)
end_m_enc = default_timer()
print("Message encryption time = ", (end_m_enc - start_m_enc) * 1000)
encrypted_string = encrypted_bytes.decode()
fernet_keystring = key.decode()

# Write encrypted data to file
file2 = open(r"encrypted_compressed_data.txt", "wb")
file2.write(encrypted_bytes)
file2.close()

# Write unencrypted key string to file
file3 = open(r"unencrypted_fernet_keystring.txt", "w")
file3.write(fernet_keystring)
file3.close()

# Generate RSA public-private key pair and write to file 
# (In practice, private key will be kept secret)
keyPair = RSA.generate(3072)

pubKey = keyPair.publickey()
pubKey_towrite = "Public key: \nn = \n" + str(pubKey.n) + "\n\ne = \n" + str(pubKey.e)
pubKeyPEM = pubKey.exportKey()
pubKey_towrite += "\n \n " + pubKeyPEM.decode('utf-8')

file4 = open(r"RSA_public_key.txt", "w")
file4.write(pubKey_towrite)
file4.close()

privKey_towrite = "Private key: \nn = \n" + str(pubKey.n) + "\n\nd = \n" + str(keyPair.d)
privKeyPEM = keyPair.exportKey()
privKey_towrite += "\n\n " + privKeyPEM.decode('utf-8')

file5 = open(r"RSA_private_key.txt", "w")
file5.write(privKey_towrite)
file5.close()

# Encrypt Fernet key using RSA public key
encryptor = PKCS1_OAEP.new(pubKey)
start_k_enc = default_timer()
encrypted_key = encryptor.encrypt(key)
end_k_enc = default_timer()
print("Key encryption time = ", (end_k_enc - start_k_enc) * 1000)

# Write encrypted key to file
file6 = open(r"encrypted_fernet_key.txt", "wb")
file6.write(encrypted_key)
file6.close()

## Transmission of encrypted file and encrypted key would occur here

# Decrypt Fernet key using RSA private key
decryptor = PKCS1_OAEP.new(keyPair)
start_k_dec = default_timer()
decrypted_key = decryptor.decrypt(encrypted_key)
end_k_dec = default_timer()
print("Key decryption time = ", (end_k_dec - start_k_dec) * 1000)

# Write decrypted key to file
file7 = open(r"decrypted_fernet_keystring.txt", "w")
file7.write(decrypted_key.decode())
file7.close()

# Decrypt data received using Fernet key
fernet_d = Fernet(decrypted_key)
start_m_dec = default_timer()
decrypted_bytes = fernet_d.decrypt(encrypted_bytes)
end_m_dec = default_timer()
print("Message decryption time = ", (end_m_dec - start_m_dec) * 1000)
bits = BitArray(bytes = decrypted_bytes)

# Write decrypted data to file
file8 = open(r"decrypted_compressed_data.txt", "wb")
file8.write(decrypted_bytes)
file8.close()

# Remove padding and decompress data, store reconstructed image in img_recon
decrypted_string = bits.bin[str_pad:]
start_decomp = default_timer()
final_arr = h.decompress(decrypted_string)
end_decomp = default_timer()
print("Decompression time = ", (end_decomp - start_decomp) * 1000)
img_recon = np.array(final_arr)
img_recon = np.reshape(img_recon, shape)

# Check whether reconstructed image is the same as original image, output of this should be 0
print("No of pixels in error from original image = " , np.sum(img_recon - img != 0))
