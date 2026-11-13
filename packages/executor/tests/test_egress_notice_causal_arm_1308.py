# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""The causal sentence of the egress-denial notice is conditional on the arm (review 1307, leg 1308).

`egress_deny_notice` closed every match with "the sandbox network path closing the
connection, not a message from the peer". Peer review 1307 WATCHED a real peer accept
and close on a destination the allowlist DOES carry, inside a real sandbox, and the
sentence printed anyway; and the same connect, refused by the destination and observed
as `Connection refused` from the guest's own host, arrives in-sandbox in close wording,
so the old sentence denied a refusal at the moment of the refusal. No literal separates
the two transport faces (their non-digit text is identical), so the arm the function
already computes is the only honest discriminator:

- destination NOT listed  -> the causal claim stands (venya itself gave no path),
- destination listed      -> names, counts, path, and an explicit "which side closed
  is not said here" — nothing more,
- no destination readable -> same stop, the file is named instead of a host.

Every conditional here is pinned from BOTH directions: a backwards gate (claim in the
listed arm, absent in the not-listed arm) reddens one cell of the pair, so the split
cannot silently invert.
"""

from pathlib import Path

from executor.egress_filter import EgressFilter, egress_deny_notice

# The reviewer's measured face, restated in RFC 5737 space (the tree-wide scrub
# requires example addresses in shipped files; the SHAPE is what the matcher reads).
PEER_CLOSE_STDERR = "Connection closed by 198.51.100.7 port 2401\n"
REFUSED_ARRIVES_AS_CLOSE_STDERR = "Connection closed by 198.51.100.7 port 2298\n"
DENIED_STDERR = "Connection closed by 203.0.113.9 port 22\n"
CAUSAL_CLAIM = "the sandbox network path closing the connection, not a message from the peer"
NOT_SAID = "does not say which side closed the connection"


def _egress(tmp_path: Path, body: str) -> EgressFilter:
    path = tmp_path / "egress-allowlist.txt"
    path.write_text(body)
    return EgressFilter(allowlist_path=path, dns_resolver="192.0.2.53")


class TestCausalSentenceIsConditionalOnTheArm:
    def test_listed_arm_never_claims_the_sandbox_closed_it(self, tmp_path: Path):
        """The motivating face: a permitted destination, a real peer close.

        Paired negative against the old text: the notice must NOT say the sandbox
        closed this, and must NOT say it was not the peer — that is the half the
        reviewer watched be false.
        """
        egress = _egress(tmp_path, "198.51.100.7\n")
        notice = egress_deny_notice(
            PEER_CLOSE_STDERR,
            returncode=255,
            command="ssh -p 2401 198.51.100.7 true",
            egress=egress,
            argv=["ssh", "-p", "2401", "198.51.100.7", "true"],
        )
        assert CAUSAL_CLAIM not in notice
        assert "it is not evidence that the destination refused you" not in notice
        assert NOT_SAID in notice
        # what venya DOES know survives: names, counts, path, shape.
        assert "198.51.100.7" in notice
        assert "carries 1 entry" in notice
        assert str(egress.allowlist_path) in notice
        assert "matched: connection closed by" in notice

    def test_a_refusal_reaching_this_arm_is_not_denied(self, tmp_path: Path):
        """The worse face: the destination refused; in-sandbox that arrives as close
        wording. The listed arm must not print a sentence that denies the refusal."""
        egress = _egress(tmp_path, "198.51.100.7\n")
        notice = egress_deny_notice(
            REFUSED_ARRIVES_AS_CLOSE_STDERR,
            returncode=255,
            command="ssh -p 2298 198.51.100.7 true",
            egress=egress,
            argv=["ssh", "-p", "2298", "198.51.100.7", "true"],
        )
        assert "it is not evidence that the destination refused you" not in notice
        assert CAUSAL_CLAIM not in notice

    def test_not_listed_arm_still_names_the_sandbox_as_the_closer(self, tmp_path: Path):
        """The arm where the claim is supported: no path was ever given, so no peer
        can own the close. This is the backwards half of the pair — if the condition
        were written inverted, this cell reddens while the listed cell goes green."""
        egress = _egress(tmp_path, "198.51.100.7\n")
        notice = egress_deny_notice(
            DENIED_STDERR,
            returncode=255,
            command="ssh 203.0.113.9 true",
            egress=egress,
            argv=["ssh", "203.0.113.9", "true"],
        )
        assert CAUSAL_CLAIM in notice
        assert "it is not evidence that the destination refused you" in notice
        assert "was never given a path to it" in notice
        assert NOT_SAID not in notice

    def test_the_app_log_prose_face_gets_no_notice_at_all(self, tmp_path: Path):
        """Review 1307's idle-timer line: rc 1, no network event, no port token.

        With the port guard this line matches no signature, so the function
        returns None — venya stays out of a log line about a timer entirely,
        not merely stops blaming the sandbox path for it.
        """
        egress = _egress(tmp_path, "# comments only\n")
        assert (
            egress_deny_notice(
                "worker: the client-side connection closed by our own idle timer\n",
                returncode=1,
                command="systemctl restart worker",
                egress=egress,
            )
            is None
        )

    def test_the_prose_guard_is_a_token_test_not_a_wording_test(self, tmp_path: Path):
        """Paired positive: the same prose WITH a port token still matches.

        The guard reads ` port `, not the words around it — an unexpected
        transport face phrased oddly is still labelled, so the narrowing
        cannot silently eat the class it was added beside.
        """
        from executor.egress_filter import find_deny_signature

        assert find_deny_signature("worker: the client-side connection closed by our own idle timer\n") is None
        assert (
            find_deny_signature("worker: the socket connection closed by our own idle handler port 9101\n")
            == "connection closed by"
        )

    def test_no_destination_arm_stops_at_names_and_counts(self, tmp_path: Path):
        """A matched shape whose command names no host: the file is named, no blame lands."""
        egress = _egress(tmp_path, "198.51.100.7\n")
        notice = egress_deny_notice(
            "Connection closed by 203.0.113.9 port 12345\n",
            returncode=255,
            command="iptables -L -n",
            egress=egress,
        )
        assert CAUSAL_CLAIM not in notice
        assert "No destination could be read from this command" in notice
        assert NOT_SAID in notice

    def test_the_intake_kex_face_follows_the_same_arm_split(self, tmp_path: Path):
        """The conditional gates the sentence, not the entry: the original intake
        shape (`kex... remote host`) prints the claim only when the file does not
        carry the destination it names."""
        kex = "kex_exchange_identification: Connection closed by remote host\n"
        argv = ["ssh", "db.internal.example", "true"]
        e = _egress(tmp_path, "db.internal.example\n")
        listed = egress_deny_notice(kex, returncode=255, command=" ".join(argv), egress=e, argv=argv)
        assert CAUSAL_CLAIM not in listed
        e2 = _egress(tmp_path, "other.internal.example\n")
        unlisted = egress_deny_notice(kex, returncode=255, command=" ".join(argv), egress=e2, argv=argv)
        assert CAUSAL_CLAIM in unlisted

    def test_notice_carries_no_allowlist_contents_under_the_new_prose(self, tmp_path: Path):
        """The content contract survives the rewrite: names and counts, never entries."""
        egress = _egress(tmp_path, "secret-relay.internal.example\n198.51.100.77\n")
        notice = egress_deny_notice(
            PEER_CLOSE_STDERR,
            returncode=255,
            command="ssh 198.51.100.77 true",
            egress=egress,
            argv=["ssh", "198.51.100.77", "true"],
        )
        assert "secret-relay.internal.example" not in notice
        assert "carries 2 entries" in notice
