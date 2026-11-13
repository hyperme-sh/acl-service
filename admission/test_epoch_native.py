"""Cross-language native contract, run only in the CI contract container."""
import json
from pathlib import Path
from unittest import TestCase

from epoch_verifier import EpochStatusVerifier, EpochManifestVerifier, SettledEpochVerifier, PrivateGrantVerifier


def encode(value):
    return json.dumps(value, separators=(',', ':'), allow_nan=False).encode()


class NativeEpochTests(TestCase):
    def setUp(self):
        self.verifier = EpochStatusVerifier()
        self.manifests = EpochManifestVerifier()
        self.selection = SettledEpochVerifier()
        self.grants = PrivateGrantVerifier()
        self.rows = json.loads(Path('epoch-fixture.json').read_bytes())

    def matches(self, row, *, now=10000, skew=0, maximum=1000):
        return self.verifier.matches_status(encode(row['proof']), encode(row['expected']),
            now_ms=now, skew_ms=skew, policy_max_age_ms=maximum)

    def test_typescript_signed_live_and_cancelled_status_match_rust(self):
        for row in self.rows:
            self.assertTrue(self.matches(row))
            self.assertTrue(self.matches(row, now=11000))
            self.assertFalse(self.matches(row, now=11001))
            self.assertFalse(self.matches(row, now=9999))
            self.assertTrue(self.matches(row, now=9999, skew=1))
            self.assertFalse(self.matches(row, now=12001, maximum=5000))

    def test_typescript_private_grant_signatures_and_exact_binding(self):
        for row in self.rows:
            proof,expected = row['grant'],row['grantExpected']
            self.assertTrue(self.grants.matches_grant(encode(proof),encode(expected)))
            for field,value in [('ownerPub','bad'),('object','other'),('accessor','other'),
                ('from',101),('until',201),('stated',1-expected['stated']),('epoch',4),
                ('owner','other'),('grantRevision',8),('itemCiphertextDigest','b'*64)]:
                self.assertFalse(self.grants.matches_grant(encode(proof),encode({**expected,field:value})))
            for field,value in [('signature','0'*128),('grantBytes','00')]:
                self.assertFalse(self.grants.matches_grant(encode({**proof,field:value}),encode(expected)))
            duplicate = encode(expected).replace(b'"epoch":3',b'"epoch":3,"epoch":3')
            self.assertFalse(self.grants.matches_grant(encode(proof),duplicate))
            self.assertFalse(self.grants.matches_grant(encode(list(proof.values())),encode(expected)))

    def test_changed_context_and_signature_refuse(self):
        original = self.rows[1]
        for field, value in [('object','other'),('accessor','other'),('epoch',4),
                             ('grantRevision',8),('revisionId','c'*64),('stated',0),('ownerPub','bad')]:
            row = json.loads(json.dumps(original))
            row['expected'][field] = value
            self.assertFalse(self.matches(row), field)
        original['proof']['signature'] = '0' * 128
        self.assertFalse(self.matches(original))

    def test_arrays_duplicate_fields_and_malformed_input_refuse(self):
        row = self.rows[1]
        proof, expected = encode(row['proof']), encode(row['expected'])
        duplicates = proof.replace(b'"epoch":3', b'"epoch":3,"epoch":3')
        for raw in [b'{', b'\xff', duplicates, encode(list(row['proof'].values()))]:
            self.assertFalse(self.verifier.matches_status(raw, expected,
                now_ms=10000, skew_ms=0, policy_max_age_ms=1000))
        for name in ['proof','expected']:
            changed = json.loads(json.dumps(row))
            changed[name]['zookie'] = list(changed[name]['zookie'].values())
            self.assertFalse(self.matches(changed))

    def test_typescript_signed_manifests_bind_the_complete_snapshot(self):
        for row in self.rows:
            expected = encode(row['manifestExpected'])
            document = row['manifest']
            self.assertTrue(self.manifests.matches_manifest(encode(document), expected))
            for path, value in [('signature','0'*128),('aclSnapshot','a'*64),('epoch',2)]:
                changed = json.loads(json.dumps(document))
                changed['manifest'][path] = value
                self.assertFalse(self.manifests.matches_manifest(encode(changed), expected))
            changed = json.loads(json.dumps(document))
            changed['snapshot']['entries'][0]['stated'] = 1 - changed['snapshot']['entries'][0]['stated']
            self.assertFalse(self.manifests.matches_manifest(encode(changed), expected))
            changed = json.loads(json.dumps(document))
            changed['snapshot']['entries'][0] = list(changed['snapshot']['entries'][0].values())
            self.assertFalse(self.manifests.matches_manifest(encode(changed), expected))
            duplicated = encode(document).replace(b'"epoch":1', b'"epoch":1,"epoch":1')
            self.assertFalse(self.manifests.matches_manifest(duplicated, expected))
            other = {**row['manifestExpected'], 'ownerPub': 'wrong'}
            self.assertFalse(self.manifests.matches_manifest(encode(document), encode(other)))

    def test_signed_finalization_settlement_and_current_acl(self):
        row = self.rows[1]['selection']
        self.assertTrue(self.selection.matches_settled(encode(row)))
        for field, value in [('nowMs',3600099),('minimumEpoch',2),('expectedEpoch',2),
                             ('anchorFinalizationId','a'*64),('expectedRevisionId','b'*64)]:
            self.assertFalse(self.selection.matches_settled(encode({**row,field:value})))
        for mutate in ['acl','signature','duplicate','future']:
            changed = json.loads(json.dumps(row))
            if mutate == 'acl': changed['current']['entries'][0]['stated'] = 0
            if mutate == 'signature': changed['finalizations'][0]['proof']['signature'] = '0'*128
            if mutate == 'duplicate': changed['finalizations'].append(changed['finalizations'][0])
            if mutate == 'future': changed['finalizations'][0]['seenAt'] = row['nowMs']+1
            self.assertFalse(self.selection.matches_settled(encode(changed)))
        duplicate = encode(row).replace(b'"nowMs":3600100',b'"nowMs":3600100,"nowMs":3600100')
        self.assertFalse(self.selection.matches_settled(duplicate))
