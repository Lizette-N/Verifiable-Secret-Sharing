from __future__ import annotations

from dataclasses import dataclass
from math import ceil
import secrets
import time

import PC
import Signatures


def empty_timing():
    return {
        "commitment_time": 0.0,
        "opening_proofs_time": 0.0,
        "ack_creation_time": 0.0,
        "ack_signature_verification_time": 0.0,
        "batch_open_time": 0.0,
        "transcript_check_time": 0.0,
        "recon_share_verification_time": 0.0,
        "lagrange_time": 0.0,
        "sharing_total_time": 0.0,
        "reconstruction_total_time": 0.0,
        "total_time": 0.0,
    }


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


def variable_initialization(numberOfNodes):
    m = 234
    q = 251

    if numberOfNodes < q:
        n = numberOfNodes
    else:
        raise ValueError("n must be smaller than q=251, because node IDs must be distinct nonzero elements in the field.")

    t = ceil(n / 2) - 1
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


def sharing_phase(numberOfnodes, timing):
    dealer_mode = None
    # dealer_mode = "invalid_share"
    # dealer_mode = "missing_share"
    # dealer_mode = "invalid_transcript"

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

    make_malicious(nodes)

    start = time.perf_counter()
    v, w = PC.Commit(pp, poly, n)
    timing["commitment_time"] += time.perf_counter() - start

    start = time.perf_counter()
    shares = send_shares(pp, v, w, poly, n)
    timing["opening_proofs_time"] += time.perf_counter() - start

    if dealer_mode == "invalid_share":
        print("Dealer is malicious and sends an invalid SHARE to node 3")
        shares[2]["share"] = shares[2]["share"] + 1

    if dealer_mode == "missing_share":
        print("Dealer is malicious and sends no SHARE to node 3")
        shares[2] = None

    for node, share in zip(nodes, shares):
        if share is not None:
            node.receive_share(share)

    ACK = collect_acks(pp, t, nodes, delta, timing)

    valid_sigma = []
    signed_nodes = []

    for ack in ACK:
        node_id = ack["node"]
        verification_key = nodes[node_id - 1].verification_key

        start = time.perf_counter()
        valid = Signatures.Verify(pp, verification_key, v, ack["signature"])
        timing["ack_signature_verification_time"] += time.perf_counter() - start

        if valid:
            valid_sigma.append(ack)
            signed_nodes.append(node_id)

    I = []

    for node in nodes:
        if node.id not in signed_nodes:
            I.append(node.id)

    start = time.perf_counter()
    s, pi_bold = PC.BatchOpen(pp, poly, I, w)
    timing["batch_open_time"] += time.perf_counter() - start

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
        start = time.perf_counter()
        result = checks(pp, t, node.id, transcript, shares, nodes)
        timing["transcript_check_time"] += time.perf_counter() - start

        node.output = result

    return pp, t, q, nodes


def make_malicious(nodes):
    if len(nodes) > 1:
        nodes[1].malicious = True
        nodes[1].malicious_mode = "invalid_ack"

    if len(nodes) > 2:
        nodes[2].malicious = True
        nodes[2].malicious_mode = "invalid_ack"

    if len(nodes) > 3:
        nodes[3].malicious = True
        nodes[3].malicious_mode = "invalid_recon"

    if len(nodes) > 4:
        nodes[4].malicious = True
        nodes[4].malicious_mode = "invalid_recon"

    if len(nodes) > 5:
        nodes[5].malicious = True
        nodes[5].malicious_mode = "silent"

    if len(nodes) > 6:
        nodes[6].malicious = True
        nodes[6].malicious_mode = "silent"


def send_shares(pp, v, w, s, n):
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

        shares.append(share)

    return shares


def collect_acks(pp, t, nodes, delta, timing):
    ACK = []
    deadline = 2 * delta

    ack_arrival_times = {
        # 3: 3 * delta,
    }

    for node in nodes:
        if node.malicious and node.malicious_mode == "silent":
            continue

        start = time.perf_counter()
        ack = node.create_ack(pp, t)
        timing["ack_creation_time"] += time.perf_counter() - start

        if ack is None:
            continue

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


def reconstruction_phase(pp, t, q, nodes, timing):
    RECON = []

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

        start = time.perf_counter()
        valid_share = PC.Verify(pp, v, node_id, share, proof)
        timing["recon_share_verification_time"] += time.perf_counter() - start

        if valid_share:
            T.append((node_id, share))

        if len(T) == t + 1:
            start = time.perf_counter()
            secret = lagrange_interpolate_at_zero(T, q)
            timing["lagrange_time"] += time.perf_counter() - start

            return secret

    return None


def create_recon(node):
    if node.output is None or node.output == 0:
        return None

    commitment, share, proof = node.output

    if node.malicious and node.malicious_mode == "silent":
        return None

    if node.malicious and node.malicious_mode == "invalid_recon":
        share = share + 1

    return {
        "type": "RECON",
        "node": node.id,
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


def algorithm1(numberOfnodes, print_result=True):
    timing = empty_timing()

    total_start = time.perf_counter()

    sharing_start = time.perf_counter()
    pp, t, q, nodes = sharing_phase(numberOfnodes, timing)
    timing["sharing_total_time"] = time.perf_counter() - sharing_start

    reconstruction_start = time.perf_counter()
    secret = reconstruction_phase(pp, t, q, nodes, timing)
    timing["reconstruction_total_time"] = time.perf_counter() - reconstruction_start

    timing["total_time"] = time.perf_counter() - total_start

    if print_result:
        print("secret:", secret)

        print("\nRuntime analysis")
        print("----------------")
        print(f"Commitment time:                  {timing['commitment_time']:.6f} seconds")
        print(f"Opening proofs time:              {timing['opening_proofs_time']:.6f} seconds")
        print(f"ACK creation time:                {timing['ack_creation_time']:.6f} seconds")
        print(f"ACK signature verification time:  {timing['ack_signature_verification_time']:.6f} seconds")
        print(f"Batch open time:                  {timing['batch_open_time']:.6f} seconds")
        print(f"Transcript check time:            {timing['transcript_check_time']:.6f} seconds")
        print(f"RECON share verification time:    {timing['recon_share_verification_time']:.6f} seconds")
        print(f"Lagrange interpolation time:      {timing['lagrange_time']:.6f} seconds")
        print(f"Sharing phase total:              {timing['sharing_total_time']:.6f} seconds")
        print(f"Reconstruction phase total:       {timing['reconstruction_total_time']:.6f} seconds")
        print(f"Total runtime:                    {timing['total_time']:.6f} seconds")

        dealer_time = (
            timing["commitment_time"]
            + timing["opening_proofs_time"]
            + timing["ack_signature_verification_time"]
            + timing["batch_open_time"]
        )

        verification_time = (
            timing["ack_creation_time"]
            + timing["transcript_check_time"]
        )

        reconstruction_time = (
            timing["recon_share_verification_time"]
            + timing["lagrange_time"]
        )

        print("\nGrouped runtime analysis")
        print("------------------------")
        print(f"Dealing time:          {dealer_time:.6f} seconds")
        print(f"Verification time:     {verification_time:.6f} seconds")
        print(f"Reconstruction time:   {reconstruction_time:.6f} seconds")

    return secret, timing


def run_experiment(numberOfnodes, numberOfRuns):
    totals = empty_timing()
    secrets = []

    for _ in range(numberOfRuns):
        secret, timing = algorithm1(numberOfnodes, print_result=False)
        secrets.append(secret)

        for key in totals:
            totals[key] += timing[key]

    averages = {}

    for key in totals:
        averages[key] = totals[key] / numberOfRuns

    dealer_time = (
        averages["commitment_time"]
        + averages["opening_proofs_time"]
        + averages["ack_signature_verification_time"]
        + averages["batch_open_time"]
    )

    verification_time = (
        averages["ack_creation_time"]
        + averages["transcript_check_time"]
    )

    reconstruction_time = (
        averages["recon_share_verification_time"]
        + averages["lagrange_time"]
    )

    print(f"Ran algorithm1 {numberOfRuns} times with n = {numberOfnodes}")
    print("Secrets:", secrets)

    print("\nAverage runtime analysis")
    print("------------------------")
    print(f"Commitment time:                  {averages['commitment_time']:.6f} seconds")
    print(f"Opening proofs time:              {averages['opening_proofs_time']:.6f} seconds")
    print(f"ACK creation time:                {averages['ack_creation_time']:.6f} seconds")
    print(f"ACK signature verification time:  {averages['ack_signature_verification_time']:.6f} seconds")
    print(f"Batch open time:                  {averages['batch_open_time']:.6f} seconds")
    print(f"Transcript check time:            {averages['transcript_check_time']:.6f} seconds")
    print(f"RECON share verification time:    {averages['recon_share_verification_time']:.6f} seconds")
    print(f"Lagrange interpolation time:      {averages['lagrange_time']:.6f} seconds")
    print(f"Sharing phase total:              {averages['sharing_total_time']:.6f} seconds")
    print(f"Reconstruction phase total:       {averages['reconstruction_total_time']:.6f} seconds")
    print(f"Total runtime:                    {averages['total_time']:.6f} seconds")

    print("\nGrouped average runtime analysis")
    print("--------------------------------")
    print(f"Dealing time:          {dealer_time:.6f} seconds")
    print(f"Verification time:     {verification_time:.6f} seconds")
    print(f"Reconstruction time:   {reconstruction_time:.6f} seconds")

    return averages


run_experiment(numberOfnodes=250, numberOfRuns=10)