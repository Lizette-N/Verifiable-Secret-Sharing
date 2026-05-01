from __future__ import annotations

from dataclasses import dataclass
import hashlib
from inspect import Signature
import secrets
from typing import Sequence
import PC
import Signatures
from dataclasses import dataclass


##def field_modulus(pp: PublicParameters) -> int:
##  return int(pp.F["modulus"])
##----------------------------------------Node Functions----------------------------------------##
@dataclass
class Node: # repræsentere en node i systemet
    id: int # nodes ummer/index
    signing_key: object # private signing key - bruges til at signere ACKs
    verification_key: object # public verification key - bruges af andre noder for at tjekke gyldigheden af nodes ACKs
    malicious: bool = False # false -> ærlige node, true -> ondsindet node
    share_msg: dict | None = None # Gemmer den SHARE besked, noden modtager fra dealeren.
    output: object = None #Gemmer hvad noden outputter efter sharing phase.

# def receive_share(self, share_msg):
#     self.share_msg = share_msg

# def create_ack(self, pp, t):
#     if self.share_msg is None:
#         return None
#     commitment = self.share_msg["commitment"]

#     valid_share = (
#         PC.DegCheck(pp, commitment, t)
#         and PC.Verify(
#                   pp,
#                   commitment,
#                   self.share_msg["node"],
#                   self.share_msg["share"],
#                   self.share_msg["proof"],
#               )
#           )

#           if not valid_share:
#               return None

#           if self.malicious and self.malicious_mode == "silent":
#               return None

#           if self.malicious and self.malicious_mode == "invalid_ack":
#               wrong_message = "fake commitment"
#               sigma_i = Signatures.Sign(pp, self.signing_key, wrong_message)
#           else:
#               sigma_i = Signatures.Sign(pp, self.signing_key, commitment)

#           return {
#               "type": "ACK",
#               "node": self.id,
#               "signature": sigma_i,
#           }




def checkAndVerify(shares, pp, t, n, signing_keys):
    ACK = []

    for i in range (1, n+1):
        share = shares[i-1]

        if PC.DegCheck(pp, share["commitment"], t) and (PC.Verify(
            pp, 
            share["commitment"], 
            share["node"], 
            share["share"], 
            share["proof"])
        ):
            sigma_i = Signatures.Sign(pp, signing_keys[i], share["commitment"])
            ### PRINT TESTERS
            print(f"\nNode {i} created signature:")
            print(sigma_i)
            print("Signature length:", len(sigma_i), "bytes")
            ### PRINT TESTERS
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
    t = 3 # t degree also t malicious nodes, also t+1 shares needed for reconstruction
    q = 19 # must be prime
    delta = 1 # maximum network latency
    poly = sample_random_polynomial(t, m, q) # Sample a t-degree random polynomial s(·) with s(0) = m
    n = 2 * t + 1 # choose min. number of nodes n which fullfills n >= 2t+1
    print(poly)
    print("n = " + str(n))
    return t, q, n, delta, poly

def broadcast(message, nodes):
    return [message for _ in nodes]

#nonce_commitment = R = g^k mod p
#c = H(R, v) mod q
#responce= z = k + c * sk_i mod q


# w = r() aka det tilfældige polynomium
# poly = s() aka det hemmelige polynomium
# v = [g^s(1) * h^r(1), g^s(2) * h^r(2), ..., g^s(n) * h^r(n)] aka commitment til det hemmelige polynomium
# I = malicious nodes aka ikke sendt ACK
# sigma = signatures for ACKs fra de ærlige nodes aka sendt ACK
# pp = G F g h

def sharingPhase():
    t , q, n, delta, poly = variableInitialization()
    pp = PC.Setup(q)
    
    nodes = []

    for i in range(1, n + 1):
        sk_i, pk_i = Signatures.GenerateKeyPair(pp)
        nodes.append(Node(i, sk_i, pk_i))

    signing_keys = {node.id: node.signing_key for node in nodes}
    verification_keys = {node.id: node.verification_key for node in nodes}
    
    ### PRINT TESTERS --------------------------------------------------- ###
    print("\nCreated nodes:", [node.id for node in nodes])
    print("Signing key IDs:", list(signing_keys.keys()))
    print("Verification key IDs:", list(verification_keys.keys()))
    ### PRINT TESTERS --------------------------------------------------- ###
    
    #time starts time = 0
    v, w = PC.Commit(pp, poly, n)
    shares = sendShares(pp, v, w, poly, n)
    #print(shares)
    ACK = checkAndVerify(shares, pp, t, n, signing_keys)
    
    ## waits until (2*delta)
    validSigma = [] # 
    signed_nodes = []
    I = []
    for ack in ACK:
        node = ack["node"]
        signature = ack["signature"] # sigma_i

        valid = Signatures.Verify(pp, verification_keys[node], v, signature)
        ### PRINT TESTERS
        print(f"\nDealer verifies signature from node {node}:")
        print(signature)
        print("Valid:", valid)
        ### PRINT TESTERS
        if valid:
            validSigma.append(ack)
            signed_nodes.append(node)
    ### PRINT TESTERS
    print(f"\nValid signatures received from nodes:")
    for ack in validSigma:
        print("node:", ack["node"], "signature length:", len(ack["signature"]))
    ### PRINT TESTERS
    for node in range(1, n + 1):
        if node not in signed_nodes:
            I.append(node)
    print(w) 
    # s sharesne for hvert node der mangler ( malicious)
    # piBold beviset for hver node der mangler (malicious) aka r(i) for hver node der mangler
    # pi er r(i) som er valid opening proof
    s, piBold = PC.BatchOpen(pp, poly, I, w)
    print("s:" + str(s)) 
    
    
    for i in range(1, n + 1):# kig på hver node
        result = checks(pp,t,v,i,validSigma,s,piBold,I,ACK,shares,verification_keys)            
        print(f"Node {i} output:", result)

        
def checks(pp,t,v,i,validSigma,s,piBold,I,ACK,shares,verification_keys):
    holds = False
    Icheck = []
    if(ACK[i]["signature"] in validSigma): # sigma_i er i valid_sigma
        if len(validSigma) >=t+1:#if (sigma.len()>=2*t+1)
            if PC.BatchVerify(pp, v, I, s, piBold): # batch verity er true
                for j in range(len(ACK)): # kig på hver node
                    if ACK[j]["signature"] not in validSigma: # laver liste af missing signature
                        Icheck = ACK[j]["node"] # I indeholder alle nodes uden signatures
                if Icheck == I: # sammenligner med i 
                    return (v,s[i],piBold[i]) # returner v, share s[i] og proof pi[i])
                                # if all true return (v,s_i,pi_i)
        
    return 0 # else return 0

# def checks(pp, t, v, i, validSigma, piBold, I, ACK,shares):
#     Icheck = []
#     if any(ack["node"] == i for ack in validSigma):
#         if len(validSigma) >= 2 * t + 1:
#             if PC.BatchVerify(pp, v, I, s, piBold):
#                 valid_nodes = [ack["node"] for ack in validSigma]

#                 for node in range(1, 2 * t + 2):
#                     if node not in valid_nodes:
#                         Icheck.append(node)
#                         if i in I:
#                             pos = I.index(i)
#                             return (v, s[pos], piBold[pos])
                        
#                 if Icheck == I:
#                     for share in shares:
#                         if share["node"] == i:
#                             return (v, share["share"], share["proof"])
#     return 0





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



    