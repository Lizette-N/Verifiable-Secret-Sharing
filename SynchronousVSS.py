from __future__ import annotations

from dataclasses import dataclass
import hashlib
from inspect import Signature
from math import ceil
import secrets
from typing import Sequence
import PC
import Signatures
from dataclasses import dataclass
import time

##----------------------------------------Node Functions----------------------------------------##
@dataclass
class Node: # Represents a node in the system
    id: int # Node number/index
    signing_key: object # Private signing key - used to sign ACKs (acknowledgements)
    verification_key: object # Public verification key - used by other nodes to check validity of a node ACK (acknowledgement)
    malicious: bool = False # False -> honest node, True -> malicious node
    malicious_mode: str | None = None  # Types of malicious nodes -> None, "silent", "invalid_ack"
    share_msg: dict | None = None # Saves the "SHARE" message the node recieves from the dealer
    output: object = None # Saves the node's output after the sharing phase

    # Node receiving their share
    def receive_share(self, share_msg):
        self.share_msg = share_msg

    ## Create acknowledgement 
    # The entire flow of the phase consisting of:
    # degreecheck, verification, and signature.
    #
    # Acknowledgement consists of node ID of the node that acknowledges
    # and the signature sigma_i 
    def create_ack(self, pp, t):

        # First checks if the node has a share of the polynomial
        if self.share_msg is None:
            return None
        
        # v is the public commitment to the dealers whole secret polynomial
        # (so this is to check that the node recieved a valid share)
        v = self.share_msg["commitment"]

        # Check that it's the correct share and not another nodes share. 
        if self.share_msg["node"] != self.id:
            return None

        valid_share = (
            # Degreecheck checks that the commitment v is to a polynomial of degree at most t
            # and verify check that this nodes specific share matches the commitment v
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

        # Silent malicious node, that doesn't return an acknowledgement
        if self.malicious and self.malicious_mode == "silent":
            return None

        # Malicious node that sends invalid acknowledgement
        if self.malicious and self.malicious_mode == "invalid_ack":
            wrong_message = "fake commitment"
            sigma_i = Signatures.Sign(pp, self.signing_key, wrong_message)
        else:
            # Sign the commitment v to acknowledge that this node verified its share
            sigma_i = Signatures.Sign(pp, self.signing_key, v)

        return {
            "type": "ACK",
            "node": self.id,
            "signature": sigma_i,
        }
    
# Initialize protocol parameters for one run
def variable_initialization(numberOfNodes):
    m = 234 # The secret value, stored as the constant term s(0)
    q = 251 # Prime field modulus (largest 8 bit prime). Valid node IDs are 1,2,...,q-1

    if numberOfNodes<q: 
        n = numberOfNodes # number of nodes in the protocol
    else:
        raise ValueError("n  must be smaller than q=251, because node IDs must be distinct nonzero elements in the field.")
    

    
    t = (n-1)//2 # Polynomial degree and maximum number of malicious nodes tolerated
    delta = 1 # Maximum network latency
    poly = sample_random_polynomial(t, m, q) # t-degree random polynomial s(·) with secret m as s(0)
    
    return t, q, n, delta, poly

def sample_random_polynomial(degree: int, secret: int, q: int) -> list[int]:
    if degree < 0:
        raise ValueError("degree must be >= 0")
    if not (0 <= secret < q):
        secret %= q

    coeffs = [secret]
    for _ in range(degree):
        coeffs.append(secrets.randbelow(q))
    return coeffs

#-------------------------------Variable explanation-------------------------------##
# pp = public parameters for the protocol and commitment scheme
# poly = s(x), the secret sharing polynomial where s(0) is the secret
# w = r(x), the random blinding polynomial used in the Pedersen commitment
# v = polynomial commitment to s(x), where v[i] = g^s(i) * h^r(i).
# ACK = acknowledgement messages from nodes that verified their shares
# sigma = valid ACK signatures on the commitment v
# I = node IDs that did not send a valid ACK signature
# s = revealed shares s(i) for all nodes in I
# pi_bold = opening proofs r(i) for all revealed shares in I
# transcript = public message broadcast by the dealer after collecting ACKs

def sharing_phase(numberOfnodes):
    dealer_mode = None
    # dealer_mode = "invalid_share"
    # dealer_mode = "missing_share"
    # dealer_mode = "invalid_transcript"

    t , q, n, delta, poly = variable_initialization(numberOfnodes)
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
    
    # making the malicious nodes (not part of algorithm but needed for testing) 
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
    return pp, t, q, nodes

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

def collect_acks(pp, t, nodes, delta):
    ACK = []
    deadline = 2 * delta

    # testing delays
    ack_arrival_times = {
        # node_id: arrival_time
        # 3: 3 * delta,  # node 3 arrives at time 3 and is too late - outcomment this line to test correctness of deadline
    }

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


def algorithm1(numberOfnodes):
    total_start = time.perf_counter()

    sharing_start = time.perf_counter()
    pp, t, q, nodes = sharing_phase(numberOfnodes)
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


algorithm1(numberOfnodes=20)
## Algorithm1
    ## START PHASE 
        ## PP 
        ## CHOOSE SECRET, Q, DEGREE, N 

    ## SHARING PHASE

    ## RECONSTRUCTION PHASE



    