from __future__ import annotations
from dataclasses import dataclass
import secrets
import PC
import Signatures

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
    # The node only signs if:
    # 1. It received a SHARE message
    # 2. The SHARE message belongs to this node
    # 3. The commitment has valid degree
    # 4. The share matches the commitment
    def create_ack(self, pp, t):
        if self.share_msg is None:
            return None
        
        # v is the public commitment to the dealers whole secret polynomial
        # (so this is to check that the node recieved a valid share)
        v = self.share_msg["commitment"]

        # Check that it's the correct share and not another nodes share. 
        if self.share_msg["node"] != self.id:
            return None

        # Degreecheck checks that the commitment v is to a polynomial of degree at most t
        # and verify check that this nodes specific share matches the commitment v
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

        # Silent malicious node sends no ACK
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
    # Check that the polynomial degree is valid
    if degree < 0:
        raise ValueError("degree must be >= 0")
    
    # Make sure the secret is inside the field
    secret %= q

    # Constant term is the secret
    coeffs = [secret]

    # Remaining coefficients are sampled randomly from the field
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
    # Dealer behavior used for correctness tests
    dealer_mode = None
    # dealer_mode = "invalid_share"
    # dealer_mode = "missing_share"
    # dealer_mode = "invalid_transcript"

    # Initialize protocol variables
    t , q, n, delta, poly = variable_initialization(numberOfnodes)
    pp = PC.Setup(q)
    
    # Create nodes and generate signing keys
    nodes = []
    for i in range(1, n + 1):
        sk_i, pk_i = Signatures.GenerateKeyPair(pp)
        node = Node(
            id=i,
            signing_key=sk_i,
            verification_key=pk_i,
        )
        nodes.append(node)

    # Dealer commits to the polynomial
    v, w = PC.Commit(pp, poly, n)

    # Dealer sends one SHARE message to each node
    shares = send_shares(pp, v, w, poly, n)

    # Nodes receive their SHARE messages
    for node, share in zip(nodes, shares):
        if share is not None:
            node.receive_share(share)
        
    # Dealer collects ACK messages
    ACK = collect_acks(pp, t, nodes, delta)
    
    # Dealer keeps only valid signatures on v
    valid_sigma = [] 
    signed_nodes = []
    for ack in ACK:
        node_id = ack["node"]
        verification_key = nodes[node_id -1].verification_key

        valid = Signatures.Verify(pp,verification_key, v, ack["signature"])
        if valid:
            valid_sigma.append(ack)
            signed_nodes.append(node_id)
    
    # I contains nodes with missing or invalid ACK signatures
    I = []
    for node in nodes:
        if node.id not in signed_nodes:
            I.append(node.id)

    # Dealer opens the shares for all nodes in I
    s, pi_bold = PC.BatchOpen(pp, poly, I, w)
    
    # Dealer creates the public transcript
    transcript = {
        "commitment": v,
        "I": I,
        "sigma": valid_sigma,
        "shares": s,
        "proofs": pi_bold,
    }
    
    # Transcript is broadcast to all nodes
    broadcast_outputs = broadcast(transcript, nodes)
    for node, transcript in zip(nodes, broadcast_outputs):
        result = checks(pp,t,node.id,transcript,shares,nodes)
        node.output = result

    return pp, t, q, nodes

def send_shares(pp, v, w, s, n):
    shares = []

    # Dealer creates one SHARE message for each node
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

    # Dealer waits until time 2 * delta
    deadline = 2 * delta

    # Used for testing delayed ACK messages
    ack_arrival_times = {
        # node_id: arrival_time
        # 3: 3 * delta,  # node 3 arrives at time 3 and is too late - outcomment this line to test correctness of deadline
    }

    # Each node tries to create an ACK
    for node in nodes:
        ack = node.create_ack(pp, t)

        if ack is None:
            continue
            
        # Default arrival time is within the deadline
        arrival_time = ack_arrival_times.get(node.id, 2 * delta)
        ack["arrival_time"] = arrival_time

        # Dealer only accepts ACKs before the deadline
        if arrival_time <= deadline:
            ACK.append(ack)

    return ACK


def broadcast(message, nodes):
    # Local simulation of a broadcast channel
    return [message for _ in nodes]

def checks(pp,t,current_node_id,transcript,shares,nodes):
    # Extract transcript values
    v = transcript["commitment"]
    I = transcript["I"]
    valid_sigma = transcript["sigma"]
    s = transcript["shares"]
    pi_bold = transcript["proofs"]
    
    # Check that all included ACK signatures are valid
    for ack in valid_sigma:
        ack_node_id = ack["node"]
        ack_node = nodes[ack_node_id - 1]

        valid = Signatures.Verify(pp, ack_node.verification_key, v, ack["signature"],)
        if not valid:
            return 0
            
    # Find all nodes with valid signatures
    valid_nodes = [ack["node"] for ack in valid_sigma]

    # Compute the expected set I from the valid signatures
    expected_I = []
    for expected_node_id in range(1, len(shares) + 1):
        if expected_node_id not in valid_nodes:
            expected_I.append(expected_node_id)

    # Check that the dealer's I is correct
    if I != expected_I:
        return 0
    
    # Check that there are at least t + 1 valid signatures
    if len(valid_sigma) < t + 1:
        return 0

    # Check the revealed shares for all nodes in I
    if len(I) > 0:
        if not PC.BatchVerify(pp, v, I, s, pi_bold):
            return 0
    
    # If this node is in I, it uses the revealed share from the transcript
    if current_node_id in I:
        pos = I.index(current_node_id)
        return (v, s[pos], pi_bold[pos])
    
    # If this node signed correctly, it uses its original SHARE message
    if current_node_id in valid_nodes:
        share_msg = shares[current_node_id - 1]
        return (v, share_msg["share"], share_msg["proof"])
    
    # Otherwise the transcript is invalid
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

        # First valid commitment becomes the reconstruction commitment
        if v is None:
            v = commitment

        # Ignore shares for a different commitment
        if commitment != v:
            continue

        # Check that the reconstructed share is valid
        if PC.Verify(pp, v, node_id, share, proof):
            T.append((node_id, share))

        # t + 1 valid shares are enough to reconstruct the secret
        if len(T) == t + 1:
            secret = lagrange_interpolate_at_zero(T, q)
            return secret

    # Reconstruction failed because not enough valid shares were received
    return None

def create_recon(self):
    # Node cannot reconstruct if it did not output a valid share
    if self.output is None or self.output == 0:
        return None
    
    commitment, share, proof = self.output
    
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

        # Compute the Lagrange coefficient for point i
        for j, _ in points:
            if i != j:
                numerator = (numerator * (-j)) % q
                denominator = (denominator * (i - j)) % q

        lambda_i = numerator * pow(denominator, -1, q) % q
        secret = (secret + si * lambda_i) % q
    return secret


def algorithm1(numberOfnodes):
    # Run the sharing phase
    pp, t, q, nodes = sharing_phase(numberOfnodes)

    # Run the reconstruction phase
    secret = reconstruction_phase(pp, t, q, nodes)

    print("secret:", secret)

algorithm1(numberOfnodes=20)




    