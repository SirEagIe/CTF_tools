import tkinter as tk
import re

def xor(bin_ciphertext, bin_key):
    bin_plain = ''
    for i in range(0, len(bin_ciphertext)//8):
        bit_cipher = ''
        bit_key = ''
        bit_plain = ''
        for j in range(i*8, i*8+8):
            bit_cipher += bin_ciphertext[j]
        for j in range(((i%(len(bin_key)//8))*8), ((i%(len(bin_key)//8))*8)+8):
            bit_key += bin_key[j]
        for j in range(0, 8):
            bit_plain += str(int(bit_cipher[j]) ^ int(bit_key[j]))
        bin_plain += bit_plain
    return bin_plain

def hex_to_bin(hex_string):
    bin_string = ''
    for i in range(0, len(hex_string), 2):
        bin_1 = bin(int(hex_string[i], 16)).replace('0b', '')
        bin_2 = bin(int(hex_string[i+1], 16)).replace('0b', '')
        while len(bin_1) < 4:
            bin_1 = '0' + bin_1
        while len(bin_2) < 4:
            bin_2 = '0' + bin_2
        bin_string += bin_1 + bin_2
    return bin_string
    
def hex_to_ascii(hex_string):
    return bytes.fromhex(hex_string).decode('utf-8')
    
def bin_to_hex(bin_string):
    hex_string = hex(int(bin_string, 2)).replace('0x', '')
    if len(hex_string)%2 != 0:
        hex_string = '0' + hex_string
    return hex_string

def bin_to_ascii(bin_string):
    n = int(bin_string, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()

def ascii_to_bin(ascii_string):
    bin_string = bin(int.from_bytes(ascii_string.encode(), 'big')).replace('0b', '')
    while len(bin_string)%8 != 0:
        bin_string = '0' + bin_string
    return bin_string

def ascii_to_hex(ascii_string):
    bin_string = ascii_to_bin(ascii_string)
    hex_string = bin_to_hex(bin_string)
    return hex_string

class Field:
    def __init__(self, label_name):
        self.label = tk.Label(text=label_name)
        self.label_ascii = tk.Label(text='ascii')
        self.label_hex = tk.Label(text='hex')
        self.label_bin = tk.Label(text='bin')
        self.entry_ascii = tk.Entry(width=33)
        self.entry_hex = tk.Entry(width=33)
        self.entry_bin = tk.Entry(width=33)
        self.text_ascii = ''
        self.text_hex = ''
        self.text_bin = ''
        
    def pack(self, row=0):
        self.label.grid(row=row, column=1, pady=(10, 0))
        self.label_ascii.grid(row=row+1, column=0, padx=10)
        self.entry_ascii.grid(row=row+2, column=0, padx=10)
        self.label_hex.grid(row=row+1, column=1, padx=10)
        self.entry_hex.grid(row=row+2, column=1, padx=10)
        self.label_bin.grid(row=row+1, column=2, padx=10)
        self.entry_bin.grid(row=row+2, column=2, padx=10)
        
    def get_ascii(self):
        return self.entry_ascii.get()
        
    def get_hex(self):
        return self.entry_hex.get()
        
    def get_bin(self):
        return self.entry_bin.get()
        
    def input_ascii(self):
        ascii_string = self.entry_ascii.get()
        self.entry_hex.delete(0, 'end')
        self.entry_bin.delete(0, 'end')
        try:
            self.entry_hex.insert(0, ascii_to_hex(ascii_string))
        except:
            self.entry_hex.insert(0, '---')
        try:
            self.entry_bin.insert(0, ascii_to_bin(ascii_string))
        except:
            self.entry_bin.insert(0, '---')
        
    def input_hex(self):
        hex_string = self.entry_hex.get()
        self.entry_ascii.delete(0, 'end')
        self.entry_bin.delete(0, 'end')
        result = re.search(r'[^0123456789abcdef]', hex_string)
        if result:
            self.entry_hex.delete(0, 'end')
            self.entry_ascii.insert(0, '---')
            self.entry_hex.insert(0, '---')
            self.entry_bin.insert(0, '---')
            return
        if len(hex_string)%2 != 0:
            hex_string = '0' + hex_string
            self.entry_hex.delete(0, 'end')
            self.entry_hex.insert(0, hex_string)
        try:
            self.entry_ascii.insert(0, hex_to_ascii(hex_string))
        except:
            self.entry_ascii.insert(0, '---')
        try:
            self.entry_bin.insert(0, hex_to_bin(hex_string))
        except:
            self.entry_bin.insert(0, '---')
        
    def input_bin(self):
        bin_string = self.entry_bin.get()
        self.entry_ascii.delete(0, 'end')
        self.entry_hex.delete(0, 'end')
        
        result = re.search(r'[^01]', bin_string)
        if result:
            self.entry_bin.delete(0, 'end')
            self.entry_ascii.insert(0, '---')
            self.entry_hex.insert(0, '---')
            self.entry_bin.insert(0, '---')
            return
        while len(bin_string)%8 != 0:
            bin_string = '0' + bin_string
        self.entry_bin.delete(0, 'end')
        self.entry_bin.insert(0, bin_string)
        try:
            self.entry_ascii.insert(0, bin_to_ascii(bin_string))
        except:
            self.entry_ascii.insert(0, '---')
        try:
            self.entry_hex.insert(0, bin_to_hex(bin_string))
        except:
            self.entry_hex.insert(0, '---')

    def clear(self):
        self.entry_ascii.delete(0, 'end')
        self.entry_hex.delete(0, 'end')
        self.entry_bin.delete(0, 'end')
        
    
class InputField(Field):
    def __init__(self, label_name):
        Field.__init__(self, label_name)
        self.button_ascii= tk.Button(text='Input in ascii', command=self.input_ascii)
        self.button_hex = tk.Button(text='Input in hex', command=self.input_hex)
        self.button_bin= tk.Button(text='Input in bin', command=self.input_bin)
        
    def pack(self, row=0):
        self.label.grid(row=row, column=1, pady=(10, 0))
        self.label_ascii.grid(row=row+1, column=0, padx=10)
        self.entry_ascii.grid(row=row+2, column=0, padx=10)
        self.button_ascii.grid(row=row+3, column=0, padx=10, pady=(5, 0))
        self.label_hex.grid(row=row+1, column=1, padx=10)
        self.entry_hex.grid(row=row+2, column=1, padx=10)
        self.button_hex.grid(row=row+3, column=1, padx=10, pady=(5, 0))
        self.label_bin.grid(row=row+1, column=2, padx=10)
        self.entry_bin.grid(row=row+2, column=2, padx=10)
        self.button_bin.grid(row=row+3, column=2, padx=10, pady=(5, 0))


class OutputField(Field):
    def set(self, bin_string):
        self.entry_bin.delete(0, 'end')
        self.entry_bin.insert(0, bin_string)
        self.input_bin()
    
    def add(self, bin_string):
        while len(bin_string)%8 != 0:
            bin_string = '0' + bin_string
        self.entry_bin.insert('end', bin_string)
        try:
            self.entry_ascii.insert('end', bin_to_ascii(bin_string))
        except:
            self.entry_ascii.insert('end', '---')
        try:
            self.entry_hex.insert('end', ''+bin_to_hex(bin_string))
        except:
            self.entry_hex.insert('end', '---')
            
    def add_ascii(self, ascii_string):
        self.entry_ascii.insert('end', '|'+ascii_string)
        
        
class Window:
    def __init__(self):
        self.ciphertext_field = InputField('Ciphertext')
        self.ciphertext_field.pack(0)
        self.key_field = InputField('Key')
        self.key_field.pack(4)
        self.button_xor = tk.Button(text='XOR', command=self.xor)
        self.length_of_key_lable = tk.Label(text='Length of key')
        self.length_of_key_entry = tk.Entry(width=33)
        self.button_brute_xor = tk.Button(text='Brute XOR', command=self.brute_xor)
        self.length_of_key_lable.grid(row=8, column=1, padx=10, pady=(10, 0))
        self.length_of_key_entry.grid(row=9, column=1, padx=10)
        self.button_brute_xor.grid(row=10, column=1, padx=10, pady=(5, 0))
        self.button_xor.grid(row=11, column=1, padx=10, pady=(10, 0))
        self.plaintext_field = OutputField('Plaintext')
        self.plaintext_field.pack(12)
        self.plaintext = ''
        
    def xor(self):
        bin_plain = xor(self.ciphertext_field.get_bin(), self.key_field.get_bin())
        self.plaintext_field.set(bin_plain)
        
    def brute_xor(self):
        try:
            length_of_key = int(self.length_of_key_entry.get())    
        except:
            self.plaintext_field.clear()
            return
        self.plaintext = ''
        for i in range(0, 2**(length_of_key*8)):
            key = bin(i).replace('0b', '')
            print(key)
            while len(key) != length_of_key*8:
                key = '0' + key
            bin_plain = xor(self.ciphertext_field.get_bin(), key)
            try:
                self.plaintext += bin_to_ascii(bin_plain).replace('\n', '').replace('\r', '')
                self.plaintext += '\n'
            except:
                pass
        file = open('output.txt', 'w')
        file.write(self.plaintext)
        file.close()


root = tk.Tk()
root.title('XOR')
root.geometry("670x420")

w = Window()

root.mainloop()