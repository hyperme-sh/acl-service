"""Wallet rotation witness over one protected source and installed signer policy."""
import base64
import copy
import json
import time
from cryptography.hazmat.primitives.asymmetric import ec
from history_admission import HistoryAdmission, _record, _peer_inputs
from statement_source import StatementSource, encoded
from acl_service.domain.history_store import AdmissionRejected, HistoryConflict
from acl_service.infrastructure.witness_signer import WitnessKey, WitnessSigner


class RotationWitnessSource:
    def __init__(self, store, *, policy_at, witness_policy, kid, private_key, clock=time.time):
        if not store.require_authority_checkpoint or not store.has_freshness:
            raise ValueError('protected rotation source required')
        self.store, self.policy_at, self.witness_policy = store, policy_at, witness_policy
        self.kid, self.private_key, self.clock = kid, private_key, clock

    def attest_wallet_rotation(self, principal, request, *, cancel=lambda: None):
        at = int(self.clock())
        policy = copy.deepcopy(self.policy_at(at))
        request = json.loads(encoded(request))
        if len(encoded(request)) > 65536 or principal not in policy['activePrincipals']:
            raise AdmissionRejected('rotation request refused')
        def guard():
            cancel()
            if int(self.clock()) != at or self.policy_at(at) != policy:
                raise HistoryConflict('rotation authority changed')
        guard()
        # Same source lock as admission and recovery; signing policy remains
        # leased until the history/floor transaction has successfully committed.
        with self.witness_policy.locked_policy() as signing_policy:
            if signing_policy is None or signing_policy.jwks != policy['trust']['jwks']:
                raise AdmissionRejected('rotation signing policy mismatch')
            jwk = next((key for key in signing_policy.jwks['keys'] if key['kid'] == self.kid), None)
            if jwk is None:
                raise AdmissionRejected('rotation signer unavailable')
            def coordinate(value):
                return int.from_bytes(base64.urlsafe_b64decode(value+'='*(-len(value)%4)), 'big')
            public = ec.EllipticCurvePublicNumbers(coordinate(jwk['x']), coordinate(jwk['y']), ec.SECP256R1()).public_key()
            key = WitnessKey(self.kid, jwk['notBefore'], jwk['notAfter'], public)
            signer = WitnessSigner(key, self.private_key, clock=lambda: int(self.clock()))
            with self.store._transaction(write=True, before_commit=guard) as db:
                guard()
                accounts = StatementSource._accounts(self, db)
                account = accounts.get(principal)
                if account is None:
                    raise AdmissionRejected('unknown rotation owner')
                native = HistoryAdmission(self.store, grant_for=lambda _:None,
                    trust_at=lambda _:policy['trust'], clock=self.clock)
                result = json.loads(native._run_verifier(principal, at, genesis=_record(account.genesis),
                    entries=[_record(row) for row in account.entries], peers=_peer_inputs(principal, accounts),
                    rotationRequest=request))
                if set(result) != {'issuedAt','claims','heads'} or set(result['heads']) != set(accounts):
                    raise AdmissionRejected('invalid rotation result')
                for owner, head in result['heads'].items():
                    if type(head) is not int or not 0 <= head <= 9007199254740991:
                        raise AdmissionRejected('invalid rotation head')
                    self.store._observe_floor(db, owner, head)
                guard()
                lifetime = min(900, key.not_after-result['issuedAt'])
                token = signer.sign_verified(result['claims'], issued_at=result['issuedAt'], lifetime=lifetime)
                guard()
            guard()
        guard()
        return token
