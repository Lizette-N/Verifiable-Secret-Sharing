import contextlib
import io
import time


def import_without_output(module_name):
    with contextlib.redirect_stdout(io.StringIO()):
        return __import__(module_name)


Async = import_without_output("AsynchronousVSS")
SECRET = 234


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
    start = time.perf_counter()

    with contextlib.redirect_stdout(io.StringIO()):
        setup_start = time.perf_counter()
        t, q, n, polynomial = Async.variable_initialization(number_of_nodes)
        pp = Async.PC.Setup(q)
        nodes = []

        for node_id in range(1, n + 1):
            signing_key, verification_key = Async.Signatures.GenerateKeyPair(pp)
            nodes.append(Async.Node(node_id, signing_key, verification_key))
        setup_time = time.perf_counter() - setup_start

        bad_nodes = list(range(1, min(bad_node_count, n) + 1))
        for node_id in bad_nodes:
            nodes[node_id - 1].malicious = True
            nodes[node_id - 1].malicious_mode = malicious_type

        dealing_start = time.perf_counter()
        commitment, witness = Async.PC.Commit(pp, polynomial, n)
        shares = Async.send_shares(pp, commitment, witness, polynomial, n)
        delivered_shares = [dict(share) for share in shares]

        dealer_target = 3 if n >= 3 else 1
        if dealer_type == "incorrect_share":
            delivered_shares[dealer_target - 1]["share"] += 1
        elif dealer_type == "missing_share":
            delivered_shares[dealer_target - 1] = None

        for node, share in zip(nodes, delivered_shares):
            if share is not None:
                node.receive_share(share)
        dealing_time = time.perf_counter() - dealing_start

        verification_start = time.perf_counter()
        try:
            valid_sigma, signed_nodes = Async.wait_for_enough_valid_signatures(
                pp,
                t,
                nodes,
                commitment,
            )
        except RuntimeError:
            valid_sigma = []
            signed_nodes = set()

        expected_I = [node.id for node in nodes if node.id not in signed_nodes]
        opened_shares, opened_proofs = Async.PC.BatchOpen(pp, polynomial, expected_I, witness)
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
            node.output = Async.checks(pp, t, node.id, transcript, delivered_shares, nodes)
        verification_time = time.perf_counter() - verification_start

        reconstruction_start = time.perf_counter()
        secret = Async.reconstruction_phase(pp, t, q, nodes)
        reconstruction_time = time.perf_counter() - reconstruction_start

    elapsed = time.perf_counter() - start
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
    print("runtime")
    print(f"  setup/keygen:     {setup_time:.6f} seconds")
    print(f"  dealing:          {dealing_time:.6f} seconds")
    print(f"  verification:     {verification_time:.6f} seconds")
    print(f"  reconstruction:   {reconstruction_time:.6f} seconds")
    print(f"  total:            {elapsed:.6f} seconds")
    print(f"result: {'PASS' if correct else 'FAIL'}")

    return correct


def run_all_correctness_tests():
    scenarios = [
        {
            "name": "baseline honest dealer and honest nodes",
            "kwargs": {
                "number_of_nodes": 20,
                "bad_node_count": 0,
                "dealer_type": "honest",
            },
        },
        {
            "name": "silent malicious nodes",
            "kwargs": {
                "number_of_nodes": 20,
                "bad_node_count": 2,
                "malicious_type": "silent",
                "dealer_type": "honest",
            },
        },
        {
            "name": "invalid ACK malicious nodes",
            "kwargs": {
                "number_of_nodes": 20,
                "bad_node_count": 2,
                "malicious_type": "invalid_ack",
                "dealer_type": "honest",
            },
        },
        {
            "name": "invalid RECON malicious nodes",
            "kwargs": {
                "number_of_nodes": 20,
                "bad_node_count": 2,
                "malicious_type": "invalid_recon",
                "dealer_type": "honest",
            },
        },
        {
            "name": "dealer sends incorrect share",
            "kwargs": {
                "number_of_nodes": 20,
                "bad_node_count": 0,
                "dealer_type": "incorrect_share",
            },
        },
        {
            "name": "dealer sends no share",
            "kwargs": {
                "number_of_nodes": 20,
                "bad_node_count": 0,
                "dealer_type": "missing_share",
            },
        },
        {
            "name": "dealer broadcasts wrong transcript",
            "kwargs": {
                "number_of_nodes": 20,
                "bad_node_count": 0,
                "dealer_type": "wrong_transcript",
            },
        },
        {
            "name": "too many malicious nodes",
            "kwargs": {
                "number_of_nodes": 10,
                "bad_node_count": 4,
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
        results.append(run_correctness_test(**scenario["kwargs"]))

    passed = sum(1 for result in results if result)
    print("\nAsynchronous correctness summary")
    print("--------------------------------")
    print(f"passed: {passed}/{len(results)}")
    print(f"overall result: {'PASS' if all(results) else 'FAIL'}")

    return all(results)


if __name__ == "__main__":
    run_all_correctness_tests()
