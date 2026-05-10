"""
Integrity verification facade for the SAGA interaction ledger.
"""
from typing import Optional

from saga.security.interaction_ledger import InteractionLedger


class IntegrityVerifier:
    def __init__(self, ledger: Optional[InteractionLedger] = None):
        self.ledger = ledger or InteractionLedger()

    def verify_ledger_integrity(self):
        return self.ledger.verify_ledger_integrity()


def verify_ledger_integrity(ledger: Optional[InteractionLedger] = None):
    return (ledger or InteractionLedger()).verify_ledger_integrity()
