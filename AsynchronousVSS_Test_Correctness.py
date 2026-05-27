import contextlib
import io
import time


def import_without_output(module_name):
    with contextlib.redirect_stdout(io.StringIO()):
        return __import__(module_name)


Async = import_without_output("AsynchronousVSS")
SECRET = 234


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
        "setup_keygen_time": 0.0,
    }


def grouped_times(timing):
    dealer_time = (
        timing["commitment_time"]
        + timing["opening_proofs_time"]
        + timing["ack_signature_verification_time"]
        + timing["batch_open_time"]
    )
    verification_time = timing["ack_creation_time"] + timing["transcript_check_time"]
    reconstruction_time = timing["recon_share_verification_time"] + timing["lagrange_time"]

    return dealer_time, verification_time, reconstruction_time


def timed_reconstruction_phase(pp, t, q, nodes, timing):
    recon_messages = []

    for node in nodes:
        recon = Async.create_recon(node)
        if recon is not None:
            recon_messages.append(recon)

    commitment = None
    accepted_points = []

    for recon in recon_messages:
        node_id = recon["node"]
        recon_commitment = recon["commitment"]
        share = recon["share"]
        proof = recon["proof"]

        if commitment is None:
            commitment = recon_commitment

        if recon_commitment != commitment:
            continue

        start = time.perf_counter()
        valid = Async.PC.Verify(pp, commitment, node_id, share, proof)
        timing["recon_share_verification_time"] += time.perf_counter() - start

        if valid:
            accepted_points.append((node_id, share))

        if len(accepted_points) >= 2 * t + 1:
            start = time.perf_counter()
            secret = Async.lagrange_interpolate_at_zero(accepted_points, q)
            timing["lagrange_time"] += time.perf_counter() - start
            return secret

    return None


def run_correctness_test(
    number_of_nodes=20,
    bad_node_count=0,
    malicious_type="silent",
    dealer_type="honest",
):
    """
    Run one asynchronous VSS correctness scenario.

    malicious_type options: "silent", "invalid_ack", "invalid_recon"
    dealer_type options: "honest", "incorrect_share", "missing_share", "wrong_transcript"
    """
    timing = empty_timing()
    total_start = time.perf_counter()

    with contextlib.redirect_stdout(io.StringIO()):
        setup_start = time.perf_counter()
        t, q, n, polynomial = Async.variable_initialization(number_of_nodes)
        pp = Async.PC.Setup(q)
        nodes = []

        for node_id in range(1, n + 1):
            signing_key, verification_key = Async.Signatures.GenerateKeyPair(pp)
            nodes.append(Async.Node(node_id, signing_key, verification_key))
        timing["setup_keygen_time"] = time.perf_counter() - setup_start

        bad_nodes = list(range(1, min(bad_node_count, n) + 1))
        for node_id in bad_nodes:
            nodes[node_id - 1].malicious = True
            nodes[node_id - 1].malicious_mode = malicious_type

        sharing_start = time.perf_counter()
        start = time.perf_counter()
        commitment, witness = Async.PC.Commit(pp, polynomial, n)
        timing["commitment_time"] += time.perf_counter() - start

        start = time.perf_counter()
        shares = Async.send_shares(pp, commitment, witness, polynomial, n)
        timing["opening_proofs_time"] += time.perf_counter() - start

        delivered_shares = [dict(share) for share in shares]

        dealer_target = 3 if n >= 3 else 1
        if dealer_type == "incorrect_share":
            delivered_shares[dealer_target - 1]["share"] += 1
        elif dealer_type == "missing_share":
            delivered_shares[dealer_target - 1] = None

        for node, share in zip(nodes, delivered_shares):
            if share is not None:
                node.receive_share(share)

        valid_sigma = []
        signed_nodes = set()
        threshold = 2 * t + 1

        for node in nodes:
            start = time.perf_counter()
            ack = node.create_ack(pp, t)
            timing["ack_creation_time"] += time.perf_counter() - start

            if ack is None:
                continue

            node_id = ack["node"]
            if node_id in signed_nodes:
                continue

            start = time.perf_counter()
            valid_ack = Async.Signatures.Verify(
                pp,
                nodes[node_id - 1].verification_key,
                commitment,
                ack["signature"],
            )
            timing["ack_signature_verification_time"] += time.perf_counter() - start

            if not valid_ack:
                continue

            valid_sigma.append(ack)
            signed_nodes.add(node_id)

            if len(valid_sigma) >= threshold:
                break

        expected_I = [node.id for node in nodes if node.id not in signed_nodes]
        start = time.perf_counter()
        opened_shares, opened_proofs = Async.PC.BatchOpen(pp, polynomial, expected_I, witness)
        timing["batch_open_time"] += time.perf_counter() - start

        transcript_I = expected_I

        if dealer_type == "wrong_transcript":
            transcript_I = expected_I[1:] if expected_I else [1]

        transcript = {
            "commitment": commitment,
            "I": transcript_I,
            "sigma": valid_sigma,
            "shares": opened_shares,
            "proofs": opened_proofs,
        }

        for node in nodes:
            start = time.perf_counter()
            node.output = Async.checks(pp, t, node.id, transcript, delivered_shares, nodes)
            timing["transcript_check_time"] += time.perf_counter() - start

        timing["sharing_total_time"] = time.perf_counter() - sharing_start

        reconstruction_start = time.perf_counter()
        secret = timed_reconstruction_phase(pp, t, q, nodes, timing)
        timing["reconstruction_total_time"] = time.perf_counter() - reconstruction_start

    timing["total_time"] = time.perf_counter() - total_start
    dealer_time, verification_time, reconstruction_time = grouped_times(timing)
    accepted_outputs = sum(1 for node in nodes if node.output != 0)
    missing_ack_count = len(expected_I)
    expected_success = (
        dealer_type != "wrong_transcript"
        and len(valid_sigma) >= 2 * t + 1
        and accepted_outputs > 0
    )
    correct = (secret == SECRET) if expected_success else (secret is None)

    print("Asynchronous VSS correctness test")
    print("---------------------------------")
    print(f"nodes: {n}")
    print(f"threshold t: {t}")
    print(f"bad nodes: {bad_nodes}")
    print(f"malicious type: {malicious_type if bad_nodes else 'none'}")
    print(f"dealer type: {dealer_type}")
    print(f"valid ACKs: {len(valid_sigma)}")
    print(f"nodes in I: {transcript_I}")
    print(f"missing valid ACK count: {missing_ack_count}")
    print(f"nodes accepting output: {accepted_outputs}/{n}")
    print(f"reconstructed secret: {secret}")
    print(f"expected secret: {SECRET if expected_success else None}")
    print("\nRuntime analysis")
    print("----------------")
    print(f"Dealing time:          {dealer_time:.6f} seconds")
    print(f"Verification time:     {verification_time:.6f} seconds")
    print(f"Reconstruction time:   {reconstruction_time:.6f} seconds")
    print(f"result: {'PASS' if correct else 'FAIL'}")

    return correct


def run_top_level_algorithm_test(number_of_nodes=20):
    start = time.perf_counter()
    output = io.StringIO()

    with contextlib.redirect_stdout(output):
        Async.algorithm2(numberOfNodes=number_of_nodes)

    elapsed = time.perf_counter() - start
    printed_output = output.getvalue()
    correct = f"secret: {SECRET}" in printed_output

    print("Asynchronous top-level algorithm test")
    print("-------------------------------------")
    print(f"called: algorithm2(numberOfNodes={number_of_nodes})")
    print(f"expected printed secret: {SECRET}")
    print(f"time: {elapsed:.6f} seconds")
    print(f"result: {'PASS' if correct else 'FAIL'}")

    return correct


def run_all_correctness_tests():
    scenarios = [
        {
            "name": "top-level algorithm2",
            "top_level": True,
            "kwargs": {
                "number_of_nodes": 50,
            },
        },
        {
            "name": "baseline honest dealer and honest nodes",
            "kwargs": {
                "number_of_nodes": 50,
                "bad_node_count": 0,
                "dealer_type": "honest",
            },
        },
        {
            "name": "silent malicious nodes",
            "kwargs": {
                "number_of_nodes": 50,
                "bad_node_count": 2,
                "malicious_type": "silent",
                "dealer_type": "honest",
            },
        },
        {
            "name": "invalid ACK malicious nodes",
            "kwargs": {
                "number_of_nodes": 50,
                "bad_node_count": 2,
                "malicious_type": "invalid_ack",
                "dealer_type": "honest",
            },
        },
        {
            "name": "invalid RECON malicious nodes",
            "kwargs": {
                "number_of_nodes": 50,
                "bad_node_count": 2,
                "malicious_type": "invalid_recon",
                "dealer_type": "honest",
            },
        },
        {
            "name": "dealer sends incorrect share",
            "kwargs": {
                "number_of_nodes": 50,
                "bad_node_count": 0,
                "dealer_type": "incorrect_share",
            },
        },
        {
            "name": "dealer sends no share",
            "kwargs": {
                "number_of_nodes": 50,
                "bad_node_count": 0,
                "dealer_type": "missing_share",
            },
        },
        {
            "name": "dealer broadcasts wrong transcript",
            "kwargs": {
                "number_of_nodes": 50,
                "bad_node_count": 0,
                "dealer_type": "wrong_transcript",
            },
        },
        {
            "name": "too many malicious nodes",
            "kwargs": {
                "number_of_nodes": 50,
                "bad_node_count": 18,
                "malicious_type": "silent",
                "dealer_type": "honest",
            },
        },
    ]

    results = []
    print("\nRunning all asynchronous correctness tests")
    print("==========================================")
    for index, scenario in enumerate(scenarios, start=1):
        print(f"\nTest {index}: {scenario['name']}")
        print("=" * (8 + len(str(index)) + len(scenario["name"])))
        if scenario.get("top_level"):
            results.append(run_top_level_algorithm_test(**scenario["kwargs"]))
        else:
            results.append(run_correctness_test(**scenario["kwargs"]))

    passed = sum(1 for result in results if result)
    print("\nAsynchronous correctness summary")
    print("--------------------------------")
    print(f"passed: {passed}/{len(results)}")
    print(f"overall result: {'PASS' if all(results) else 'FAIL'}")

    return all(results)


if __name__ == "__main__":
    run_all_correctness_tests()
