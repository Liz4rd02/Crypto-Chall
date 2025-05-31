from Crypto.Util.number import long_to_bytes

#from secret import flag
#p, q = getPrime(64), getPrime(64)
#n = p*q
e = 65537
#print(n)
#m = bytes_to_long(flag)
#print(pow(m, e, n))

c = 46228309104141229075992607107041922411
n = 176278749487742942508568320862050211633

#factorized n on https://factordb.com with input n.
#12271643243945501447<20> · 14364722473065221639<20>

p = 12271643243945501447
q = 14364722473065221639
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
m = pow(c, d, n)
m = long_to_bytes(m)
print(m)