from __future__ import annotations
from dataclasses import dataclass
import secrets
import PC
import Signatures

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

        # Degreecheck checks that the commitment v is to a polynomial of degree at most 2t
        # and verify check that this nodes specific share matches the commitment v
        valid_share = (
            PC.DegCheck(pp, v, 2*t)
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
    
    t = (n-1)//3 # Polynomial degree and maximum number of malicious nodes tolerated
    poly = sample_random_polynomial(2*t, m, q) # Sample a 2*t-degree random polynomial s(·) with s(0) = m

    return t, q, n, poly

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
    t , q, n, poly = variable_initialization(numberOfnodes)
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

    ## wait for 2t + 1 valid signatures on v
    valid_sigma, signed_nodes = wait_for_enough_valid_signatures(pp, t, nodes, v)

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
    broadcast_outputs = reliable_broadcast(transcript, nodes)
    for node, transcript in zip(nodes, broadcast_outputs):
        result = checks(pp,t,node.id,transcript,shares,nodes)
        node.output = result

    return pp, t, q, nodes

def reliable_broadcast(message, nodes):
    #simulation of byzantine reliable broadcast
    return [message for _ in nodes]

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

def wait_for_enough_valid_signatures(pp, t, nodes, v):
    valid_acks = []
    signed_nodes = set()

    # 2 * t + 1 required
    threshold = 2 * t + 1

    # Dealer checks ACKs until enough valid signatures are found
    for node in nodes:
        ack = node.create_ack(pp, t)

        # If no valid ack, skip to next node
        if ack is None:
            continue
        
        node_id = ack["node"]

        # Do not count the same node twice
        if node_id in signed_nodes:
            continue

        verification_key = nodes[node_id -1].verification_key

        # Verify that the ACK signature is valid on v
        valid = Signatures.Verify(pp, verification_key, v, ack["signature"]
        )

        if not valid:
            continue
        
        valid_acks.append(ack)
        signed_nodes.add(node_id)

        # The dealer can continue when 2t + 1 valid signatures are found
        if len(valid_acks) >= threshold:
            break
    
    # If the dealer cannot collect enough ACKs, sharing cannot complete
    if len(valid_acks) < threshold:
        raise RuntimeError("Dealer did not recieve 2t +1 valic signatures on v.")

    return valid_acks, signed_nodes

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
    
    # Check that there are at least 2t + 1 valid signatures
    if len(valid_sigma) < 2 * t + 1:
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

def reconstruction_phase(pp, t, q, nodes):
    RECON = []

    # Algorithm 2 line 201:
    # every node sends <RECON, s(i), pi_i>
    for node in nodes:
        recon = create_recon(node)
        if recon is not None:
            RECON.append(recon)

    v = None
    T = []

# Algorithm 2 lines 202-206:
# receive RECON messages, verify, collect 2t+1 shares
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

        # Check that the reconstructed share is valid
        if PC.Verify(pp, v, node_id, share, proof):
            T.append((node_id, share))

        # 2t + 1>= valid shares are enough to reconstruct the secret
        if len(T) >= 2*t + 1:
            secret = lagrange_interpolate_at_zero(T, q)
            return secret

    return None



def algorithm2(numberOfNodes):
    # Run the sharing phase
    pp, t, q, nodes = sharing_phase(numberOfNodes)

    # Run the reconstruction phase
    secret = reconstruction_phase(pp, t, q, nodes)
    print("secret:", secret)

algorithm2(numberOfNodes=20)


