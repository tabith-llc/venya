# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Is this key file a parseable encrypted key, or a damaged one? (#577)

One question, one call site: ``server.ca._deserialize_key`` uses this before it chooses whom to
blame for a failed load. A damaged CA key file used to be reported as a wrong passphrase, because
the only test at that branch was "did the caller supply a passphrase?" — an operator whose file is
truncated or whose armor holds a body that no longer decodes was told to re-type a passphrase that
was already correct, forever (ticket #577).

The mechanism is a second, passwordless read of the same bytes, which is the discriminating question:

* an intact ENCRYPTED key raises ``TypeError`` — the parser got far enough to know it needs a
  password, so the structure is fine and only the secret is in question;
* every damaged shape raises ``ValueError`` first — a body truncated mid-key, armor kept over a
  swapped body, armor kept over a body that is not base64 at all;
* an unencrypted key raises nothing, because it loads.

The branch is on the exception CLASS, which is documented API. Nothing in this module reads,
copies or matches a library MESSAGE: coupling to the library's sentence is exactly what #541's
blanket rule and #572 remove from the operator's view, and a message-matching probe would rot the
day the dependency changes its prose.

Scope of this helper, stated so it is not read as a general key library: it answers one question
for one caller. The CLI carries its own small probe for the same class of defect (``#572``,
``packages/cli/src/venya_cli/commands.py``); the two are deliberately NOT unified — importing the
CLI into the server is forbidden by #577's AC5, and one call site does not justify coupling two
packages' passphrase-probe semantics to a shared module. If a future row wants a single home, that
is a ``features/`` item.
"""

from cryptography.hazmat.primitives import serialization


def encrypted_key_is_parseable(key_data: bytes) -> bool:
    """True when ``key_data`` is a structurally parseable ENCRYPTED PEM private key.

    Args:
        key_data: The raw key bytes the caller already tried (and failed) to load.

    Returns:
        True only when a passwordless read reaches the "this key needs a password" answer
        (``TypeError``) — i.e. the file's structure is intact and a passphrase is a meaningful
        thing to have gotten wrong. False for a damaged file (``ValueError``) and for bytes that
        load without any password at all (an unencrypted key is not an encrypted key).
    """
    try:
        serialization.load_pem_private_key(key_data, password=None)
    except TypeError:
        return True
    except ValueError:
        return False
    return False
