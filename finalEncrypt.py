#A MILLER RABIN ENCRYPTION ALGORITHM IMPLEMENTATION 

import sys
import random
from math import log
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

sys.setrecursionlimit(1000000) #This limit prevents infinite recursion from causing an overflow


def encrypt_click():    #Function which creates the encrypt button-click actions
    textboxValue = textbox.text()
    cipherTuple = encryption(textboxValue)      #calls the encryption function
    ciphertext, decryptkey = cipherTuple
    displayciphertext = ""
    for i in ciphertext:
        displayciphertext = displayciphertext + str(i)+","  #converts the encrypted ascii numbers in list into string format for display
    displayciphertext = displayciphertext+"\nand the decryption key pair (modulus, private key) is: "+str(decryptkey)
    textbox.setText(displayciphertext)
    
def decrypt_click():    #Function which creates the decrypt button-click actions

    #user input is validated, and try-catch statements used in catching possible errors
    textboxValue = textbox.text()
    myList =[]
    myText = textboxValue.split(",")        #splits the encrypted text into list of distinct numbers (still in string format)
    try:
        for i in myText:
            if type((int(i)))==int:
                myList.append(int(i))       #converts the string format numbers into int and store in a list for decryption
    except:
        textbox.setText("There was an error in generating the cryptotext list")
    try:
        prKeyboxValue = prKeybox.text()
        if type((int(prKeyboxValue)))==int:     #confirm that inputed private key is a number
            prKey = int(prKeyboxValue)
    except:
        textbox.setText("Provide a valid private key")
    try:
        modKeyboxValue = modKeybox.text()
        if type((int(modKeyboxValue)))==int:    ##confirm that inputed modulus is a number
            modKey = int(modKeyboxValue)
    except:
        textbox.setText("Provide a valid modulus for encryption")
    try:
        decryptTuple = [myList, (modKey, prKey)]
        plaintext = decryption(decryptTuple)        #calls the decryption function
    except:
        textbox.setText("There was an error in the decryption")
    try:
        textbox.setText(plaintext)
    except:
        textbox.setText("There was an error during the display of plaintext")



def SQM(base, exp, mod):
    #fast exponentiation algorithm capable of handling huge integers
    #checks binary bit of given base, when binary bit is "one", squares the base and mutiples with previous number
    #else just multiples
    
    binaryStr = ""
    answer = 1
    s = base

    binary1 = bin(exp)[2:]
    binaryStr = binary1 [::-1]
    if binaryStr[0] == "1": 
        answer = s

    for i in binaryStr[1:]:
        s = (s*s)%mod
        if i == "1":
            answer = (answer*s)%mod
        else:
            continue

    return answer



def highBitOrder(n):
    k = int(log(n, 2))
    if k:
        x = n >> (k-1)
        if x == 1: # correct log() imprecision for very large integers
            return k - 1
        elif 2 <= x < 4:
            return k
        else: # very unlikely, but handled
            raise ValueError("high_bit_order() failed on unusual value.")
    else:
        return k



def lowBitOrder(n):
    return highBitOrder(n & -n)


def GCD(a,b):
    while b!=0:
        temporaryA = b
        b = a%b
        a = temporaryA

    return a


def egcd(a, b): #extended euclid's algorithm: derives the Euclid's bezout coefficient (the required inverse)
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def multiplicative_inverse(num, mod):  #picks the inverse from the egcd function
    g, x, y = egcd(num, mod)
    if g == 1:
        return x % mod


def millerRabin (n):

    #In this function we first rule out the first 200 small primes, also we use specific values of primes(a) for our witnesses

    num = abs(n)
    phi_n = num-1     #the formula num-1 is equivalent to (2^lowestbit)*remainder
    temporary_phi = phi_n
    myPrimeList = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
                   73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
                   157, 163, 167, 173, 179, 181, 191, 193, 197, 199]

    if num%2 == 0 and num !=2:  #checks if number is an even number
        return False
    elif num == 1:   #checks if the number given equals 1
        return False
    elif num in myPrimeList: #quick check if number is in list of first 200 primes
        return True
    else:
        lowestbit = lowBitOrder(temporary_phi)      #calculates lowest set bit
        remainder = int(phi_n/SQM(2,lowestbit,num))    #calculates remainder such that X = (2^lowestbit)*remainder

    myDict = {}
    
    for i in range(1,10):
        a = random.choice(myPrimeList)  #randomly picks witnesses to used in showing if given number is prime

        for k in range(1, lowestbit+1, 1):
            y = SQM(a, ((SQM(2, k, num)) * remainder), num)  #miller rabins formular iterated k times (and storing computed values to be re-used)
            myDict[k] = y
            
        if myDict[lowestbit] != 1:
            return False
            break
        
        for  j in range (2, lowestbit+1, 1):
            
            if myDict[j] == 1 and myDict [j-1] != (1 or -1): #continuation of miller rabins formular using pre-computed values
                return False
                break
    return True

def randomPrimeGen():
    randPrime = random.randint(256, 65536)  #generates random number and then tests if number is prime
    while millerRabin(randPrime) == False:
        randPrime = random.randint(256, 65536) #maximum length of generated prime ie key length is 64bits
    else:
        return randPrime

def modulusCalc():
    p = randomPrimeGen()
    q = randomPrimeGen()
    while p == q:
        q = randomPrimeGen()    #checks and ensures we have 2 distincts primes
    else:
        modulus = p*q
        phi_n = (p-1)*(q-1)     #we calculate the modulus using 2 random primes and return it with the euler function phi_n

    return modulus, phi_n

def publicKeyGen():
    e = randomPrimeGen()        #we generate and use a random prime as the public key
    mod1, phi_n = modulusCalc()     #we obtain a modulus and its phi
    while GCD(e, phi_n) != 1 or millerRabin(e) ==False:     #ensures that gcd of phi_n and e equals one
        e = randomPrimeGen()
    else:
        public_key = (e, mod1, phi_n)
        return public_key               #returns tuple of public key, the modulus and its phi

def privateKeyGen(pubKey):
    e, mod2, phi = pubKey
    d = multiplicative_inverse(e, phi)      #calculates the private key as the inverse of the public key

    return d

def encryption(plaintext):
    encryptKey = publicKeyGen()     #generate public key tuple
    e, mod3, phi = encryptKey
    d = privateKeyGen(encryptKey)   #calculate private key from public key

    cipher = [SQM(ord(char),e,mod3)for char in plaintext]  #converts each plaintext character's ascii value to an encrypted number in a list
                                                            #using RSA encryption formula : E(x) = x^(e) (mod n)

    return cipher, (d, mod3)        #returns encrypted text and private key tuple

def decryption(cipherTuple):
    ciphertext, decryptKey = cipherTuple
    d, mod4 = decryptKey
    plain = [chr(SQM(char, d, mod4))for char in ciphertext] #decrypts each cryptotext number to original ascii value of plaintext and converts to alphabet
    plainText = ''.join(plain)                              #using RSA decryption formula : D(x) = y^(d) (mod n)

    return plainText

def GUI():
    #initialize global variables of our GUI window to permit being called by other functions
    global myapplication
    global decryptbutton
    global encryptbutton
    global prKeybox
    global modKeybox
    global textbox
    global myWidget
    
    #create GUI main window
    myapplication = QApplication(sys.argv)
    myWidget = QWidget()
    myWidget.setWindowTitle('RSA CIPHER IMPLEMENTATION')

    # creates a text-box for inputing and displaying text
    textbox = QLineEdit(myWidget)
    textbox.move(20, 20)
    textbox.resize(680,430)
    textboxLabel = QLabel(myWidget)
    textboxLabel.setText("Input and Display Text Area:")
    textboxLabel.move(20, 450)

    # creates a textbox for inputing the modulus
    modKeybox = QLineEdit(myWidget)
    modKeybox.move(400, 570)
    modKeybox.resize(150,50)
    modulusLabel = QLabel(myWidget)
    modulusLabel.setText("Input Modulus:")
    modulusLabel.move(400, 550)

    # creates textbox for inputing the private key for decryption
    prKeybox = QLineEdit(myWidget)
    prKeybox.move(560, 570)
    prKeybox.resize(150,50)
    privateKeyLabel = QLabel(myWidget)
    privateKeyLabel.setText("Input Private Key:")
    privateKeyLabel.move(560, 550)

 
    # Set the window size
    myWidget.resize(820, 650)
 
    # Create an encryption button in the window
    encryptbutton = QPushButton('Encrypt', myWidget)
    encryptbutton.move(20,580)

    # Create a decryption button in the window
    decryptbutton = QPushButton('Decrypt', myWidget)
    decryptbutton.move(140,580)

    # Connects the buttons to the actions in the encrypt and decrypt functions
    encryptbutton.clicked.connect(encrypt_click)
    decryptbutton.clicked.connect(decrypt_click)

    #displays the widget and its offsprings
    myWidget.show()
    myapplication.exec_()


GUI()
