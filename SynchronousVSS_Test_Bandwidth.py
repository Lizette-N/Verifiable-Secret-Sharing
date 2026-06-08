from __future__ import annotations
from dataclasses import dataclass
import pickle
import secrets
import PC
import Signatures


@dataclass
class Node:
    id: int
    signing_key: object
    verification_key: object
    malicious: bool = False
    malicious_mode: str | None = None
    share_msg: dict | None = None
    output: object = None

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


def byte_size(obj) -> int:
    return len(pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL))


def empty_bandwidth_metrics():
    return {
        "sharing_dealer_sent_bytes": 0,
        "sharing_dealer_received_bytes": 0,
        "sharing_receivers_sent_bytes": 0,
        "sharing_receivers_received_bytes": 0,
        "sharing_broadcast_bytes": 0,
    }


def add_bytes(metrics, name, obj, multiplier=1):
    metrics[name] += byte_size(obj) * multiplier


def kb(x):
    return x / 1024


def mb(x):
    return x / (1024 * 1024)


def print_bandwidth_metrics(metrics, n):
    dealer_total = (
        metrics["sharing_dealer_sent_bytes"]
        + metrics["sharing_dealer_received_bytes"]
    )

    receiver_avg = (
        metrics["sharing_receivers_sent_bytes"]
        + metrics["sharing_receivers_received_bytes"]
    ) / n

    network_total = (
        metrics["sharing_dealer_sent_bytes"]
        + metrics["sharing_receivers_sent_bytes"]
    )

    print("\nSharing phase bandwidth analysis")
    print("--------------------------------")
    print(f"Dealer bandwidth:          {mb(dealer_total):.6f} MB")
    print(f"Receiver avg bandwidth:    {kb(receiver_avg):.3f} KB")
    print(f"Logical network total:     {mb(network_total):.6f} MB")
    print(f"Broadcast contribution:    {mb(metrics['sharing_broadcast_bytes']):.6f} MB")

    print("\nDetailed breakdown")
    print("------------------")
    print(f"Dealer sent:               {kb(metrics['sharing_dealer_sent_bytes']):.3f} KB")
    print(f"Dealer received:           {kb(metrics['sharing_dealer_received_bytes']):.3f} KB")
    print(f"Receivers sent total:      {kb(metrics['sharing_receivers_sent_bytes']):.3f} KB")
    print(f"Receivers received total:  {kb(metrics['sharing_receivers_received_bytes']):.3f} KB")
    print(f"Receiver avg sent:         {kb(metrics['sharing_receivers_sent_bytes'] / n):.3f} KB")
    print(f"Receiver avg received:     {kb(metrics['sharing_receivers_received_bytes'] / n):.3f} KB")

def variable_initialization(numberOfNodes):
    m = 234
    q = 251

    if numberOfNodes < q:
        n = numberOfNodes
    else:
        raise ValueError("n must be smaller than q=251, because node IDs must be distinct nonzero elements in the field.")

    t = (n - 1) // 2
    delta = 1
    poly = sample_random_polynomial(t, m, q)

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


def sharing_phase(numberOfnodes, bandwidth_metrics):
    dealer_mode = None

    t, q, n, delta, poly = variable_initialization(numberOfnodes)
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

    v, w = PC.Commit(pp, poly, n)
    shares = send_shares(pp, v, w, poly, n, bandwidth_metrics)

    if dealer_mode == "invalid_share":
        print("Dealer is malicious and sends an invalid SHARE to node 3")
        shares[2]["share"] = shares[2]["share"] + 1

    if dealer_mode == "missing_share":
        print("Dealer is malicious and sends no SHARE to node 3")
        shares[2] = None

    for node, share in zip(nodes, shares):
        if share is not None:
            node.receive_share(share)

    ACK = collect_acks(pp, t, nodes, delta, bandwidth_metrics)

    valid_sigma = []
    signed_nodes = []

    for ack in ACK:
        node_id = ack["node"]
        verification_key = nodes[node_id - 1].verification_key

        valid = Signatures.Verify(pp, verification_key, v, ack["signature"])

        if valid:
            valid_sigma.append(ack)
            signed_nodes.append(node_id)

    I = []

    for node in nodes:
        if node.id not in signed_nodes:
            I.append(node.id)

    s, pi_bold = PC.BatchOpen(pp, poly, I, w)

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

    add_bytes(bandwidth_metrics, "sharing_dealer_sent_bytes", transcript, multiplier=n)
    add_bytes(bandwidth_metrics, "sharing_receivers_received_bytes", transcript, multiplier=n)
    add_bytes(bandwidth_metrics, "sharing_broadcast_bytes", transcript, multiplier=n)

    broadcast_outputs = broadcast(transcript, nodes)

    for node, transcript in zip(nodes, broadcast_outputs):
        result = checks(pp, t, node.id, transcript, shares, nodes)
        node.output = result

    return pp, t, q, nodes

def send_shares(pp, v, w, s, n, bandwidth_metrics):
    shares = []

    for i in range(1, n + 1):
        u, pi = PC.Open(pp, w, s, i)

        share = {
            "type": "SHARE",
            "node": i,
            "commitment": v,
            "share": u,
            "proof": pi,
        }

        add_bytes(bandwidth_metrics, "sharing_dealer_sent_bytes", share)
        add_bytes(bandwidth_metrics, "sharing_receivers_received_bytes", share)

        shares.append(share)

    return shares


def collect_acks(pp, t, nodes, delta, bandwidth_metrics):
    ACK = []
    deadline = 2 * delta

    ack_arrival_times = {
    }

    for node in nodes:
        if node.malicious and node.malicious_mode == "silent":
            continue

        ack = node.create_ack(pp, t)

        if ack is None:
            continue

        add_bytes(bandwidth_metrics, "sharing_receivers_sent_bytes", ack)
        add_bytes(bandwidth_metrics, "sharing_dealer_received_bytes", ack)

        arrival_time = ack_arrival_times.get(node.id, 2 * delta)
        ack["arrival_time"] = arrival_time

        if arrival_time <= deadline:
            ACK.append(ack)
        else:
            print(f"Node {node.id} ACK arrived at tau = {arrival_time}, too late")

    return ACK


def broadcast(message, nodes):
    return [message for _ in nodes]


def checks(pp, t, current_node_id, transcript, shares, nodes):
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

    expected_I = []

    for expected_node_id in range(1, len(shares) + 1):
        if expected_node_id not in valid_nodes:
            expected_I.append(expected_node_id)

    if I != expected_I:
        return 0

    if len(valid_sigma) < t + 1:
        return 0

    if len(I) > 0:
        if not PC.BatchVerify(pp, v, I, s, pi_bold):
            return 0

    if current_node_id in I:
        pos = I.index(current_node_id)
        return (v, s[pos], pi_bold[pos])

    if current_node_id in valid_nodes:
        share_msg = shares[current_node_id - 1]
        return (v, share_msg["share"], share_msg["proof"])

    return 0


def reconstruction_phase(pp, t, q, nodes):
    RECON = []
    n = len(nodes)

    for node in nodes:
        recon = create_recon(node)

        if recon is not None:
            RECON.append(recon)

    v = None
    T = []

    for recon in RECON:
        node_id = recon["node"]
        commitment = recon["commitment"]
        share = recon["share"]
        proof = recon["proof"]

        if v is None:
            v = commitment

        if commitment != v:
            continue

        if PC.Verify(pp, v, node_id, share, proof):
            T.append((node_id, share))

        if len(T) == t + 1:
            secret = lagrange_interpolate_at_zero(T, q)
            return secret

    return None


def create_recon(self):
    if self.output is None or self.output == 0:
        return None

    commitment, share, proof = self.output

    if self.malicious and self.malicious_mode == "silent":
        return None

    if self.malicious and self.malicious_mode == "invalid_recon":
        share = share + 1

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
    bandwidth_metrics = empty_bandwidth_metrics()
    pp, t, q, nodes = sharing_phase(numberOfnodes, bandwidth_metrics)
    secret = reconstruction_phase(pp, t, q, nodes)
    print("secret:", secret)
    print_bandwidth_metrics(bandwidth_metrics, numberOfnodes)


algorithm1(numberOfnodes=5)