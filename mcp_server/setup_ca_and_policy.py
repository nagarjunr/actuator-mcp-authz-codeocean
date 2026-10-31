"""setup_ca_and_policy.py -- one-time (per evaluation run) commissioning script:
generates a root CA, issues agent certificates for the roles used in the evaluation
battery, writes+signs a policy document, then exits. Mirrors mcp-local-authz's own
commissioning pattern (ca.ca.generate_root_ca / issue_agent_certificate,
policy_engine.policy_signing.sign_policy_file) -- reused unmodified.

Run this ONCE on the Jetson before running the evaluation harness. Re-running it
regenerates a fresh CA (invalidating any previously-issued certs saved to disk) --
intentional, so each evaluation run starts from a clean, known trust root.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ca.ca import generate_root_ca, issue_agent_certificate, ensure_private_dir, save_root_ca, write_private_file, write_public_file
from policy_engine.policy_signing import sign_policy_file

RUNTIME_DIR = Path(__file__).resolve().parent.parent / "runtime"
CA_DIR = RUNTIME_DIR / "ca"
POLICY_PATH = RUNTIME_DIR / "policy.yaml"
CERTS_DIR = RUNTIME_DIR / "certs"

POLICY_YAML = """\
schema_version: 1
metadata:
  site_id: "adam6060-rig"
  issued_by: "local-ca-v1"
  issued_at: "2026-09-13T00:00:00Z"
  description: "Roles for the ADAM-6060 physical-actuation evaluation battery."
roles:
  actuator-operator:
    description: >
      Full read+write access to the ADAM-6060 relay/DI tools. This is the ONLY role
      permitted to call write_relay -- used for legitimate signed commands in the
      evaluation battery.
    rules:
      - tools: ["read_digital_inputs", "read_relays", "write_relay", "all_relays_off"]
        effect: ALLOW
  read-only-monitor:
    description: >
      Read-only monitoring role. Used as the confused-deputy attacker's OWN
      legitimate identity in scenario 1 -- it must never be able to get write_relay
      executed, whether directly or via a relayed/forwarded call.
    rules:
      - tools: ["read_digital_inputs", "read_relays"]
        effect: ALLOW
      - tools: ["write_relay", "all_relays_off"]
        effect: DENY
        reason: "read-only-monitor has no write access to actuators"
  unauthorized-agent:
    description: >
      A role deliberately NOT granted any tool access -- used for the baseline
      unauthorized-access-rejection scenario (#8) and as a stand-in for an
      unrecognized/attacker identity.
    rules:
      - tools: ["*"]
        effect: DENY
        reason: "unauthorized-agent is granted no tool access whatsoever"
default_effect: DENY
"""


def main() -> None:
    ensure_private_dir(RUNTIME_DIR)
    ensure_private_dir(CERTS_DIR)

    ca = generate_root_ca(site_id="adam6060-rig")
    save_root_ca(ca, CA_DIR)
    print(f"Root CA generated and saved to {CA_DIR}")

    POLICY_PATH.write_text(POLICY_YAML)
    sig_path = sign_policy_file(ca, POLICY_PATH)
    print(f"Policy written to {POLICY_PATH}, signed at {sig_path}")

    for agent_id, role in [
        ("operator-01", "actuator-operator"),
        ("monitor-01", "read-only-monitor"),
        ("attacker-01", "unauthorized-agent"),
    ]:
        cert = issue_agent_certificate(ca, agent_id=agent_id, role=role)
        cert_path = CERTS_DIR / f"{agent_id}.cert.pem"
        key_path = CERTS_DIR / f"{agent_id}.key.pem"
        write_public_file(cert_path, cert.cert_pem)
        write_private_file(key_path, cert.private_key_pem)
        cert_b64_path = CERTS_DIR / f"{agent_id}.cert.b64"
        # The base64 certificate is what an agent presents as its identity, so keep it owner-only too.
        write_private_file(cert_b64_path, base64.b64encode(cert.cert_pem))
        print(f"Issued cert for {agent_id} (role={role}) -> {cert_path}")


if __name__ == "__main__":
    main()
