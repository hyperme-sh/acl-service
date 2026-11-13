"""Exclusive agent-delegation journal; no enrollment or HTTP activation."""
import json

from history_admission import HistoryAdmission, _record, _peer_inputs
from statement_source import StatementSource


class DelegationSource(StatementSource):
    """A separately provisioned scope, sharing identity and rollback protection.

    The inherited operator-only provision takes a canonical HTTPS audience in
    its second argument. The exclusive grant must cover all delegations and
    cancellations in this new scope, not an existing imported collection.
    Statement scopes cannot be read as delegation scopes or vice versa: their
    forum/audience formats are disjoint and verified on every operation.
    No startup binding or endpoint selects this source yet.
    """

    def _verify(self, accounts, doc, at, candidates, statement_only):
        principal = next(iter(accounts))
        account = accounts[principal]
        verifier = HistoryAdmission(self.store, grant_for=lambda _: None,
                                    trust_at=lambda _: doc["policy"], clock=self.clock)
        return json.loads(verifier._run_verifier(
            principal, at, genesis=_record(account.genesis),
            entries=[_record(row) for row in account.entries],
            peers=_peer_inputs(principal, accounts),
            agentGraph={"audience": doc["forum"], "rows": doc["rows"],
                        "candidates": candidates}))
