#!/user/bin/python3

qname1 = 'google1.com'
file_bl = "bl_sites.txt"
file1 = open(file_bl, "r")
array_bl = file1.read()

if qname1 in array_bl: 
    print('String', qname1, 'Found In File')
else: 
    print('String', qname1 , 'Not Found') 
file1.close() 