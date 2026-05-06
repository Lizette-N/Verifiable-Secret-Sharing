from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class SynchronousVSSTests(unittest.TestCase):
    def run_protocol(
        self,
        dealer_mode: str | None = None,
        secret: int | None = None,
        threshold: int | None = None,
        malicious_body: str | None = None,
    ) -> str:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            for filename in ("SynchronousVSS.py", "PC.py", "Signatures.py"):
                shutil.copy(ROOT / filename, temp_path / filename)

            source_path = temp_path / "SynchronousVSS.py"
            source = source_path.read_text()

            if secret is not None:
                source = re.sub(
                    r"(?m)^    m = \d+ # s\(0\)=m then s\(0\) is the secret to be shared$",
                    f"    m = {secret} # s(0)=m then s(0) is the secret to be shared",
                    source,
                    count=1,
                )
                self.assertIn(f"m = {secret}", source)

            if threshold is not None:
                source = re.sub(
                    r"(?m)^    t = \d+ # t degree also t malicious nodes, also t\+1 shares needed for reconstruction$",
                    f"    t = {threshold} # t degree also t malicious nodes, also t+1 shares needed for reconstruction",
                    source,
                    count=1,
                )
                self.assertIn(f"t = {threshold}", source)

            if dealer_mode is not None:
                source = re.sub(
                    r"(?m)^    dealer_mode = None$",
                    f'    dealer_mode = "{dealer_mode}"',
                    source,
                    count=1,
                )
                self.assertIn(f'dealer_mode = "{dealer_mode}"', source)

            if malicious_body is not None:
                source = re.sub(
                    r"(?s)def makeMalicious\(nodes\):.*?\n\n#-------------------------------Value explenation",
                    f"def makeMalicious(nodes):\n{malicious_body}\n\n#-------------------------------Value explenation",
                    source,
                    count=1,
                )
                self.assertIn(malicious_body.strip().splitlines()[0].strip(), source)

            source_path.write_text(source)

            result = subprocess.run(
                [sys.executable, "SynchronousVSS.py"],
                cwd=temp_path,
                text=True,
                capture_output=True,
                timeout=20,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
            )
            return result.stdout

    def test_honest_dealer_recovers_secret_despite_malicious_nodes(self):
        output = self.run_protocol(None)

        self.assertIn("Node 2 is malicious and sends no ACK", output)
        self.assertIn("these are illegal I:  [2, 5]", output)
        self.assertIn("Node 2 is malicious and sends no RECON", output)
        self.assertIn("Node 7 is malicious and sends wrong RECON", output)
        self.assertIn("Reconstructed secret: 234", output)

    def test_invalid_share_from_dealer_is_recovered_by_transcript(self):
        output = self.run_protocol("invalid_share")

        self.assertIn("Dealer is malicious and sends an invalid SHARE to node 3", output)
        self.assertIn("these are illegal I:  [2, 3, 5]", output)
        self.assertIn("Reconstructed secret: 234", output)

    def test_missing_share_from_dealer_is_recovered_by_transcript(self):
        output = self.run_protocol("missing_share")

        self.assertIn("Dealer is malicious and sends no SHARE to node 3", output)
        self.assertIn("these are illegal I:  [2, 3, 5]", output)
        self.assertIn("Reconstructed secret: 234", output)

    def test_invalid_transcript_is_rejected(self):
        output = self.run_protocol("invalid_transcript")

        self.assertIn("Dealer is malicious and broadcasts an invalid transcript", output)
        self.assertIn("Node 1 output: 0", output)
        self.assertIn("Node 7 output: 0", output)
        self.assertIn("Not enough valid shares", output)
        self.assertNotIn("Reconstructed secret: 234", output)

    def test_silent_node_only_does_not_block_reconstruction(self):
        output = self.run_protocol(
            malicious_body="""    nodes[1].malicious = True
    nodes[1].malicious_mode = "silent"
""",
        )

        self.assertIn("Node 2 is malicious and sends no ACK", output)
        self.assertIn("these are illegal I:  [2]", output)
        self.assertIn("Node 2 is malicious and sends no RECON", output)
        self.assertIn("Reconstructed secret: 234", output)

    def test_invalid_ack_node_is_excluded_then_can_send_valid_recon(self):
        output = self.run_protocol(
            malicious_body="""    nodes[4].malicious = True
    nodes[4].malicious_mode = "invalid_ack"
""",
        )

        self.assertIn("these are illegal I:  [5]", output)
        self.assertNotIn("Node 5 is malicious and sends wrong RECON", output)
        self.assertIn("Reconstructed secret: 234", output)

    def test_invalid_recon_node_is_rejected_without_blocking_reconstruction(self):
        output = self.run_protocol(
            malicious_body="""    nodes[6].malicious = True
    nodes[6].malicious_mode = "invalid_recon"
""",
        )

        self.assertIn("these are illegal I:  []", output)
        self.assertIn("Node 7 is malicious and sends wrong RECON", output)
        self.assertIn("Reconstructed secret: 234", output)

    def test_different_secret_is_reconstructed(self):
        output = self.run_protocol(
            secret=42,
            malicious_body="""    return
""",
        )

        self.assertIn("Reconstructed secret: 42", output)

    def test_secret_larger_than_field_is_reconstructed_mod_q(self):
        output = self.run_protocol(
            secret=300,
            malicious_body="""    return
""",
        )

        self.assertIn("Reconstructed secret: 49", output)

    def test_different_threshold_changes_n_and_still_reconstructs(self):
        output = self.run_protocol(
            threshold=4,
            malicious_body="""    nodes[1].malicious = True
    nodes[1].malicious_mode = "silent"

    nodes[4].malicious = True
    nodes[4].malicious_mode = "invalid_ack"

    nodes[7].malicious = True
    nodes[7].malicious_mode = "invalid_recon"
""",
        )

        self.assertIn("n = 9", output)
        self.assertIn("these are illegal I:  [2, 5]", output)
        self.assertIn("Node 8 is malicious and sends wrong RECON", output)
        self.assertIn("Reconstructed secret: 234", output)


if __name__ == "__main__":
    unittest.main()
