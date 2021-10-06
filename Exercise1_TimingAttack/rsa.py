#!/usr/bin/python3.6

import time
from matplotlib import pyplot as plt
import numpy as np
import math, copy, random

# Utils from
# https://github.com/arvearve/crypto/blob/master/Python_RSA_Impl/rsa.py
# https://github.com/arvearve/crypto/blob/master/Attack/output/2ms_sleep_33bit_key/data.csv

def nPrime(n):
    """ Calculates r^{-1} and n' as used in Montgomery exponentiation"""
    # n is a k-bit number.
    # r should be 2^k
    k = math.floor(math.log2(int(n))) + 1
    r = int(math.pow(2, k))
    rInverse = ModInverse(r, n)
    nPrime = (r * rInverse -1) // n
    return (r, nPrime)

# def num2bits(num):
    # bits = []
    # k = math.floor(math.log2(num)) + 1
    # for i in list(reversed(list(range(0,k)))):
        # bits.append(num >> i & 1)
    # return bits

def ModInverse(a, n):
    """ Calculates the modular inverse of a mod n.
    	http://www.wikiwand.com/en/Extended_Euclidean_algorithm#/Modular_integers
    """
    (t, new_t, r, new_r) = 0, 1, int(n), int(a)
    while new_r != 0:
        quotient = r//new_r
        (t, new_t) = (new_t, t - quotient * new_t)
        (r, new_r) = (new_r, r - quotient * new_r)
    if r > 1:
        raise ArithmeticError("ERROR: %d is not invertible modulo %d. \n r was: %d, new_r was %d " % (a, n, r, new_r))
    if t < 0:
        t = t + n
    return t

# def bits2num(bits):
        # num = 0
        # w = len(bits)
        # for i in range(w):
            # if bits[i] == 1:
                # num += (2**(w-i-1))
        # return num

def simMongomeryProduct(a, b, nprime, r, n):
    """ Montgomery product."""
    t = a * b
    m = t * nprime % r
    u = (t + m*n)//r
    return (u-n, True) if (u >= n) else (u, False)

# Modified by GC in order to attack the square 
# instead of the multiply
def isSlow(m, d, n):
        """ Montgomery binary exponentiation"""
        if n%2 != 1:
                raise ValueError("N must be odd!")
        (r, nprime) = nPrime(n)
        M_bar = (m * r) % n
        x_bar = 1 * r % n
        bit_list = d
        for e_i in bit_list:
                x_bar, slow = simMongomeryProduct(x_bar, x_bar, nprime, r, n)
                if e_i == 1:
                        x_bar, slow = simMongomeryProduct(M_bar, x_bar, nprime, r, n)
        x, slow = simMongomeryProduct(x_bar, 1, nprime, r, n)
        
        x_bar, slow = simMongomeryProduct(x_bar, x_bar, nprime, r, n)
        return slow

def ModExp(m, d, n):
        """ Montgomery binary exponentiation"""
        if n%2 != 1:
                raise ValueError("N must be odd!")
        (r, nprime) = nPrime(n)
        M_bar = (m * r) % n
        x_bar = 1 * r % n
        bit_list = d
        for e_i in bit_list:
                x_bar, slow = simMongomeryProduct(x_bar, x_bar, nprime, r, n)
                if e_i == 1:
                        x_bar, slow = simMongomeryProduct(M_bar, x_bar, nprime, r, n)
        x, slow = simMongomeryProduct(x_bar, 1, nprime, r, n)
        
        return x



print("Loading")

messages = []
signatures = []
timings = []
with open('./data.csv', 'r') as f:
    _ = f.readline() # Ignore first line (which is a column description)
    n, e = f.readline().split(',') # read in public key
    n = int(n)
    e = int(e)
    _=f.readline() # ignore third line (which is a column description)
    for line in f:
        m, s, t = [int(x) for x in line.split(',')]
        messages.append(m)
        signatures.append(s)
        timings.append(t)

# Attack code by GC
print("Attacking")

Ntraces = 739
messages = messages[:Ntraces]
signatures = signatures[:Ntraces]
timings = timings[:Ntraces]

def test(keyguess):
    found = True
    for m,s in zip(messages[0:10], signatures[0:10]):
        if(s != ModExp(m, keyguess, n)):
            found = False
    return found

# assume first bit is 1
keyguess = [1]
maxbits = 64
found = False
while(maxbits > 0 and not found):
    print("bit %d"%(len(keyguess)))
    
    M1 = []
    M2 = []
    M3 = []
    M4 = []
    # guess next d bit is 1
    for m, t in zip(messages, timings):
        if isSlow(m, keyguess+[1], n):
            M1.append(t)
        else:
            M2.append(t)
        if isSlow(m, keyguess+[0], n):
            M3.append(t)
        else:
            M4.append(t)

    print(np.average(M1)- np.average(M2), np.average(M3)- np.average(M4))

    if(np.average(M1)-np.average(M2) > np.average(M3)-np.average(M4)):
        keyguess.append(1)
    else:
        keyguess.append(0)

    print(keyguess)
    print("")

    # The check on the last bit of the key is not followed by another iteration
    # with a square, so we cannot attack it...
    # We can just bruteforce the last bit.
    if(test(keyguess+[1])):
        keyguess.append(1)
        found = True
        print("Found!")
    elif(test(keyguess+[0])):
        keyguess.append(1)
        found = True
        print("Found!")

    maxbits -= 1

knownkey = [1,1,1,1,1,1,0,1,0,0,0,0,1,0,1,1,1,1,1,0,1,0,0,1,1,0,1,0,1,1,1,1,1]
print("recovered d = ", keyguess)
print("known     d = ", knownkey)
print()

# Note: this code attacks the square step, and it is successful with 739 timings
# The original code in https://github.com/arvearve/crypto attacks the multiply
# step, if you try running it with 739 timings it does not converge
