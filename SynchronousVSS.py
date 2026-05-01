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
    malicious_mode: str | None = None  # None, "silent", "invalid_ack"
    share_msg: dict | None = None # Gemmer den SHARE besked, noden modtager fra dealeren.
    output: object = None #Gemmer hvad noden outputter efter sharing phase.

    def receive_share(self, share_msg):
        self.share_msg = share_msg

    def create_ack(self, pp, t):
        if self.share_msg is None:
            return None
        commitment = self.share_msg["commitment"]
        if self.share_msg["node"] != self.id:
            return None

        valid_share = (
            PC.DegCheck(pp, commitment, t)
            and PC.Verify(
                pp,
                commitment,
                self.share_msg["node"],
                self.share_msg["share"],
                self.share_msg["proof"],
            )
        )
        if not valid_share:
            return None

        if self.malicious and self.malicious_mode == "silent":
            return None

        if self.malicious and self.malicious_mode == "invalid_ack":
            wrong_message = "fake commitment"
            sigma_i = Signatures.Sign(pp, self.signing_key, wrong_message)
        else:
            sigma_i = Signatures.Sign(pp, self.signing_key, commitment)

        return {
            "type": "ACK",
            "node": self.id,
            "signature": sigma_i,
        }
        
        
        
        

        
def collect_acks(pp, t, nodes):
    ACK = []
    for node in nodes:
        ack = node.create_ack(pp, t)
        if ack is not None:
            ACK.append(ack)
    return ACK



#def checkAndVerify(shares, pp, t, n, signing_keys):
#    ACK = []
#
#    for i in range (1, n+1):
#        share = shares[i-1]
#
#        if PC.DegCheck(pp, share["commitment"], t) and (PC.Verify(
#            pp, 
#            share["commitment"], 
#            share["node"], 
#            share["share"], 
#            share["proof"])
#        ):
#            sigma_i = Signatures.Sign(pp, signing_keys[i], share["commitment"])
#            ### PRINT TESTERS
#            print(f"\nNode {i} created signature:")
#            print(sigma_i)
#            print("Signature length:", len(sigma_i), "bytes")
#            ### PRINT TESTERS
#            ack = {
#                "type": "ACK",
#                "node": i,
#                "signature": sigma_i,
#            }
#            ACK.append(ack)
#    return ACK 

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
        node = Node(
            id=i,
            signing_key=sk_i,
            verification_key=pk_i,
        )
        nodes.append(node)
    
    ## making malicious nodes---------------------------------------##
    nodes[1].malicious = True # node id 2 er ondsindet
    nodes[1].malicious_mode = "silent"

    nodes[4].malicious = True # node id 5 er ondsindet
    nodes[4].malicious_mode = "invalid_ack"
    

    #time starts time = 0
    v, w = PC.Commit(pp, poly, n)
    shares = sendShares(pp, v, w, poly, n)
    for node, share in zip(nodes, shares):
        node.receive_share(share)
        
    
    #print(shares)
    ACK = collect_acks(pp, t, nodes)
    
    ## waits until (2*delta)
    validSigma = [] 
    signed_nodes = []
    for ack in ACK:
        node_id = ack["node"]
        node = nodes[node_id-1] 

        valid = Signatures.Verify(pp,node.verification_key, v, ack["signature"])
        if valid:
            validSigma.append(ack)
            signed_nodes.append(node_id)
    
    I = []
    for node in nodes:
        if node.id not in signed_nodes:
            I.append(node.id)
    print("these are illegal I: ",I)
    print(w) 
    # s sharesne for hvert node der mangler ( malicious)
    # piBold beviset for hver node der mangler (malicious) aka r(i) for hver node der mangler
    # pi er r(i) som er valid opening proof
    s, piBold = PC.BatchOpen(pp, poly, I, w)
    print("s:" + str(s)) 
    
    transcript = {
        "commitment": v,
        "I": I,
        "sigma": validSigma,
        "shares": s,
        "proofs": piBold,
    }
    broadcast_outputs = broadcast(transcript, nodes)
    
    for node, transcript in zip(nodes, broadcast_outputs):
        result = checks(pp,t,node.id,transcript,shares,nodes)
        print(f"Node {node.id} output:", result)
        
    # for i in range(1, n + 1):# kig på hver node
    #     result = checks(pp,t,v,i,validSigma,s,piBold,I,shares)            
    #     print(f"Node {i} output:", result)

        
def checks(pp,t,nodeId,transcript,shares,nodes):
    v = transcript["commitment"]
    I = transcript["I"]
    validSigma = transcript["sigma"]
    s = transcript["shares"]
    piBold = transcript["proofs"]
    
    for ack in validSigma:
        ack_node_id = ack["node"]
        ack_node = nodes[ack_node_id - 1]

        if not Signatures.Verify(pp, ack_node.verification_key, v, ack["signature"]):
            return 0
    
    valid_nodes = [ack["node"] for ack in validSigma]
    #checker om I fra dealeren er korrekt
    expected_I = []
    for node_id in range(1, len(shares) + 1):
        if node_id not in valid_nodes:
            expected_I.append(node_id)

    if I != expected_I:
        return 0
    
    # Check 1: der skal være mindst t+1 gyldige signaturer
    if len(validSigma) < t + 1:
        return 0

    # Check 2: batch-verificer de shares, dealeren offentliggør for I
    if len(I) > 0:
        if not PC.BatchVerify(pp, v, I, s, piBold):
            return 0
    
    # Hvis node i mangler gyldig signatur, skal dens share være i I
    if nodeId in I:
        pos = I.index(nodeId)
        return (v, s[pos], piBold[pos])
    
    # Hvis node i har signeret gyldigt, bruger den sin oprindelige SHARE-besked
    if nodeId in valid_nodes:
        share_msg = shares[nodeId - 1]
        return (v, share_msg["share"], share_msg["proof"])
    
    # Hvis den hverken er i I eller har gyldig signatur, er transcriptet forkert
    return 0

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



    