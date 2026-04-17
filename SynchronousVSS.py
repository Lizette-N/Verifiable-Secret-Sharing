from __future__ import annotations

from dataclasses import dataclass
import hashlib
from inspect import Signature
from inspect import Signature
import secrets
from typing import Sequence
import PC
import Signatures


##def field_modulus(pp: PublicParameters) -> int:
##  return int(pp.F["modulus"])

def checkAndVerify(shares, pp, t, n, signing_keys):
    ACK = []
    for i in range (1, n+1):
        share = shares[i-1]
        if PC.DegCheck(pp, share["commitment"], t) and (PC.Verify(pp, share["commitment"], share["node"], share["share"], share["proof"])):
            sigma_i = Signatures.Sign(pp, signing_keys[i], share["commitment"])
            ack = {
                "type": "ACK",
                "node": i,
                "signature": sigma_i,
            }
            ACK.append(ack)
    return ACK 

def sendShares(pp, v, w, s, n):
    shares = []
    for i in range (1, n+1):
        u, pi = PC.Open(pp, w, s, i)

        share = {
            "type": "SHARE",
            "node": i,
            "commitment": v,
            "share": u, #s(i)
            "proof": pi, #r(i)
        }
        shares.append(share)
    
    return shares    


def sample_random_polynomial(degree: int, secret: int, q: int) -> list[int]:
    if degree < 0:
        raise ValueError("degree must be >= 0")
    if not (0 <= secret < q):
        secret %= q

    coeffs = [secret]
    for _ in range(degree):
        coeffs.append(secrets.randbelow(q))
    return coeffs

def variableInitialization():
    m = 5 # s(0)=m then s(0) is the secret to be shared
    t = 3 # t degree
    q = 19 # must be prime
    delta = 1 # maximum network latency
    s = sample_random_polynomial(t, m, q) # Sample a t-degree random polynomial s(·) with s(0) = m
    n = 2 * t + 1 # choose min. number of nodes n which fullfills n >= 2t+1
    print(s)
    print("n = " + str(n))
    return(t, q, n, delta, s, n, )


#nonce_commitment = R = g^k mod p
#c = H(R, v) mod q
#responce= z = k + c * sk_i mod q
  
  
def sharingPhase():
    t , q, n, delta, s, n, = variableInitialization()
    pp = PC.Setup(q)
    
    signing_keys = {}
    verification_keys = {}
    for i in range(1, n + 1):
        sk_i, pk_i = Signatures.GenerateKeyPair(pp)
        signing_keys[i] = sk_i
        verification_keys[i] = pk_i
    #time starts time = 0
    v, w = PC.Commit(pp, s, n)
    shares = sendShares(pp, v, w, s, n)
    #print(shares)
    ACK = checkAndVerify(shares, pp, t, n, signing_keys)
    
    ## waits until (2*delta)
    sigma = []
    I = []
    for ack in ACK:
        if ack["type"] == "ACK":
            print("ACK received from node " + str(ack["node"]) + " with signature: " + str(ack["signature"]))
            sigma.append(ack["signature"])
        else :
            I.append(ack["signature"])
    
        
    
        
def reconstructionPhase():
    a=1
    
def algorithm1():
    
    sharingPhase()
    reconstructionPhase()


algorithm1()





## Algorithm1
    ## START PHASE 
        ## PP 
        ## CHOOSE SECRET, Q, DEGREE, N 

    ## SHARING PHASE

    ## RECONSTRUCTION PHASE



    