from __future__ import annotations

from dataclasses import dataclass
import hashlib
from inspect import Signature
import secrets
from typing import Sequence
import PC
import Signatures
from dataclasses import dataclass
import time


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
        v = self.share_msg["commitment"]
        if self.share_msg["node"] != self.id:
            return None

        valid_share = (
            PC.DegCheck(pp, v, t)
            and PC.Verify(
                pp,
                v,
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
            sigma_i = Signatures.Sign(pp, self.signing_key, v)

        return {
            "type": "ACK",
            "node": self.id,
            "signature": sigma_i,
        }
        
def collect_acks(pp, t, nodes, delta):
    ACK = []
    deadline = 2 * delta

    # testing delays
    ack_arrival_times = {
        # node_id: arrival_time
        # 3: 3 * delta,  # node 3 is too late
    }
    #print("Dealer sends SHARE at tau = 0")
    #print(f"Dealer waits until tau = {deadline}")
    

    for node in nodes:
        if node.malicious and node.malicious_mode == "silent":
            #print(f"Node {node.id} is malicious and sends no ACK")
            continue

        ack = node.create_ack(pp, t)
        if ack is None:
            continue
            
        arrival_time = ack_arrival_times.get(node.id, 2 * delta)
        ack["arrival_time"] = arrival_time

        if arrival_time <= deadline:
            #print(f"Node {node.id} ACK arrived at tau = {arrival_time}")
            ACK.append(ack)
        else:
            print(f"Node {node.id} ACK arrived at tau = {arrival_time}, too late")

    return ACK


def send_shares(pp, v, w, s, n):
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

def variable_initialization():
    m = 234 # s(0)=m then s(0) is the secret to be shared
    t = 20 # t degree also t malicious nodes, also t+1 shares needed for reconstruction
    q = 251 # must be prime
    delta = 1 # maximum network latency
    poly = sample_random_polynomial(t, m, q) # Sample a t-degree random polynomial s(·) with s(0) = m
    n = 2 * t + 1 # choose min. number of nodes n which fullfills n >= 2t+1
    #print(poly)
    #print("n = " + str(n))
    return t, q, n, delta, poly

def broadcast(message, nodes):
    return [message for _ in nodes]

def checks(pp,t,current_node_id,transcript,shares,nodes):
    v = transcript["commitment"]
    I = transcript["I"]
    valid_sigma = transcript["sigma"]
    s = transcript["shares"]
    pi_bold = transcript["proofs"]
    
    for ack in valid_sigma:
        ack_node_id = ack["node"]
        ack_node = nodes[ack_node_id - 1]

        if not Signatures.Verify(pp, ack_node.verification_key, v, ack["signature"]):
            return 0
    
    valid_nodes = [ack["node"] for ack in valid_sigma]
    #checker om I fra dealeren er korrekt
    expected_I = []
    for expected_node_id in range(1, len(shares) + 1):
        if expected_node_id not in valid_nodes:
            expected_I.append(expected_node_id)

    if I != expected_I:
        return 0
    
    # Check 1: der skal være mindst t+1 gyldige signaturer
    if len(valid_sigma) < t + 1:
        return 0

    # Check 2: batch-verificer de shares, dealeren offentliggør for I
    if len(I) > 0:
        if not PC.BatchVerify(pp, v, I, s, pi_bold):
            return 0
    
    # Hvis node i mangler gyldig signatur, skal dens share være i I
    if current_node_id in I:
        pos = I.index(current_node_id)
        return (v, s[pos], pi_bold[pos])
    
    # Hvis node i har signeret gyldigt, bruger den sin oprindelige SHARE-besked
    if current_node_id in valid_nodes:
        share_msg = shares[current_node_id - 1]
        return (v, share_msg["share"], share_msg["proof"])
    
    # Hvis den hverken er i I eller har gyldig signatur, er transcriptet forkert
    return 0

def make_malicious(nodes):
    ## making malicious nodes---------------------------------------##
    # nodes[1] = node id 2 and so on, because node ids start from 1 but list index starts from 0
    
    nodes[1].malicious = True
    nodes[1].malicious_mode = "invalid_ack"

    nodes[2].malicious = True 
    nodes[2].malicious_mode = "invalid_ack"

    nodes[3].malicious = True 
    nodes[3].malicious_mode = "invalid_recon"
    
    nodes[4].malicious = True 
    nodes[4].malicious_mode = "invalid_recon"
    nodes[5].malicious = True 
    nodes[5].malicious_mode = "silent"
    nodes[6].malicious = True 
    nodes[6].malicious_mode = "silent"



#-------------------------------Variable explenation-------------------------------##
#nonce_commitment = R = g^k mod p
#c = H(R, v) mod q
#responce= z = k + c * sk_i mod q
# w = r() aka det tilfældige polynomium
# poly = s() aka det hemmelige polynomium
# v = [g^s(1) * h^r(1), g^s(2) * h^r(2), ..., g^s(n) * h^r(n)] aka commitment til det hemmelige polynomium
# I = nodes missing valid ACK signatures on v
# sigma = signatures for ACKs fra de ærlige nodes aka sendt ACK
# pp = G F g h

def sharing_phase():
    dealer_mode = None
    # dealer_mode = "invalid_share"
    # dealer_mode = "missing_share"
    # dealer_mode = "invalid_transcript"


    t , q, n, delta, poly = variable_initialization()
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
    
    # making the malicious nodes (not part of algorithem but needed for testing) 
    make_malicious(nodes)
    

    #time starts time = 0
    v, w = PC.Commit(pp, poly, n)
    shares = send_shares(pp, v, w, poly, n)
    # inplimenting malisius dealer behavior
    if dealer_mode == "invalid_share":
        print("Dealer is malicious and sends an invalid SHARE to node 3")
        shares[2]["share"] = shares[2]["share"] + 1
    if dealer_mode == "missing_share":
        print("Dealer is malicious and sends no SHARE to node 3")
        shares[2] = None
        
    for node, share in zip(nodes, shares):
        if share is not None:
            node.receive_share(share)
        
    
    #print(shares)
    ACK = collect_acks(pp, t, nodes, delta)
    
    ## waits until (2*delta)
    valid_sigma = [] 
    signed_nodes = []
    for ack in ACK:
        node_id = ack["node"]
        verification_key = nodes[node_id -1].verification_key

        valid = Signatures.Verify(pp,verification_key, v, ack["signature"])
        if valid:
            valid_sigma.append(ack)
            signed_nodes.append(node_id)
    
    I = []
    for node in nodes:
        if node.id not in signed_nodes:
            I.append(node.id)
    #print("nodes missing valid signatures I: ",I)
    #print(w) 
    # s sharesne for hvert node der mangler ( malicious)
    # pi_bold beviset for hver node der mangler (malicious) aka r(i) for hver node der mangler
    # pi er r(i) som er valid opening proof
    s, pi_bold = PC.BatchOpen(pp, poly, I, w)
    
    
    # implimenting malicious dealer behavior
    if dealer_mode == "invalid_transcript" and len(s) > 0:
        print("Dealer is malicious and broadcasts an invalid transcript")
        s = list(s)
        s[0] = s[0] + 1
        s = tuple(s)
    

    #print("s:" + str(s)) 
    
    transcript = {
        "commitment": v,
        "I": I,
        "sigma": valid_sigma,
        "shares": s,
        "proofs": pi_bold,
    }
    broadcast_outputs = broadcast(transcript, nodes)
    
    for node, transcript in zip(nodes, broadcast_outputs):
        result = checks(pp,t,node.id,transcript,shares,nodes)
        node.output = result
        #print(f"Node {node.id} output:", result)
        
    # for i in range(1, n + 1):# kig på hver node
    #     result = checks(pp,t,v,i,valid_sigma,s,pi_bold,I,shares)            
    #     print(f"Node {i} output:", result)
    
    return pp, t, q, nodes


def lagrange_interpolate_at_zero(points, q):

    secret = 0

    for i, si in points:
        numerator = 1
        denominator = 1

        for j, _ in points:
            if i != j:
                numerator = (numerator * (-j)) % q
                denominator = (denominator * (i - j)) % q

        lambda_i = numerator * pow(denominator, -1, q) % q
        secret = (secret + si * lambda_i) % q
    return secret

def create_recon(self):
    if self.output is None or self.output == 0:
        return None
    
    commitment, share, proof = self.output
    
    # making nodes send no RECON if they are silent malicious
    if self.malicious and self.malicious_mode == "silent":
        #print(f"Node {self.id} is malicious and sends no RECON")
        return None

    # making nodes send wrong RECON if they are invalidmalicious
    if self.malicious and self.malicious_mode == "invalid_recon":
        #print(f"Node {self.id} is malicious and sends wrong RECON")
        share = (share + 1) 
        
    
    return {
        "type": "RECON",
        "node": self.id,
        "commitment": commitment,
        "share": share,
        "proof": proof,
    }

def reconstruction_phase(pp, t, q, nodes):
    RECON = []

    # Algorithm 1 line 201:
    # every node sends <RECON, s(i), pi_i>
    for node in nodes:
        recon = create_recon(node)
        if recon is not None:
            RECON.append(recon)

    v = None
    T = []

# Algorithm 1 lines 202-206:
# receive RECON messages, verify, collect t+1 shares
    for recon in RECON:
        node_id = recon["node"]
        commitment = recon["commitment"]
        share = recon["share"]
        proof = recon["proof"]

        if v is None:
            v = commitment

        # All shares must belong to same commitment
        if commitment != v:
            continue

        if PC.Verify(pp, v, node_id, share, proof):
            T.append((node_id, share))

        if len(T) == t + 1:
            secret = lagrange_interpolate_at_zero(T, q)
            #print("Reconstructed secret:", secret)
            return secret

    #print("Not enough valid shares")
    return None



def algorithm1():
    total_start = time.perf_counter()

    sharing_start = time.perf_counter()
    pp, t, q, nodes = sharing_phase()
    sharing_end = time.perf_counter()

    reconstruction_start = time.perf_counter()
    secret = reconstruction_phase(pp, t, q, nodes)
    reconstruction_end = time.perf_counter()

    total_end = time.perf_counter()

    print("secret:", secret)

    print("\nRuntime analysis")
    print("----------------")
    print(f"Sharing phase:        {sharing_end - sharing_start:.6f} seconds")
    print(f"Reconstruction phase: {reconstruction_end - reconstruction_start:.6f} seconds")
    print(f"Total runtime:        {total_end - total_start:.6f} seconds")


algorithm1()
## Algorithm1
    ## START PHASE 
        ## PP 
        ## CHOOSE SECRET, Q, DEGREE, N 

    ## SHARING PHASE

    ## RECONSTRUCTION PHASE



    