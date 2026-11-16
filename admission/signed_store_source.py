"""Protected recovery/wrap writer over the current checkpointed source."""
import copy
import time
from history_admission import HistoryAdmission
from acl_service.domain.history_store import AdmissionRejected,HistoryConflict


class SignedStoreSource:
    def __init__(self,store,policy_at,*,clock=time.time):
        if not store.require_authority_checkpoint or not store.has_freshness:
            raise AdmissionRejected('signed store requires protected checkpoints')
        self.store,self.policy_at,self.clock=store,policy_at,clock

    def _run(self,principal,operation):
        at=int(self.clock());policy=copy.deepcopy(self.policy_at(at))
        if principal not in policy['activePrincipals']:
            raise AdmissionRejected('signed store principal inactive')
        def guard():
            if int(self.clock())!=at or self.policy_at(at)!=policy:
                raise HistoryConflict('signed store authority changed')
        guard()
        class GuardedAdmission(HistoryAdmission):
            def _require_evaluation(self,evaluated):
                super()._require_evaluation(evaluated);guard()
        runner=GuardedAdmission(self.store,grant_for=lambda _:None,trust_at=lambda _:copy.deepcopy(policy['trust']),clock=self.clock)
        result=operation(runner)
        guard()
        return result

    def read_store_row(self,principal,kind,target):
        return self._run(principal,lambda runner:runner.read_store_row(principal,kind,target))

    def apply_store_operation(self,principal,kind,operation):
        return self._run(principal,lambda runner:runner.apply_store_operation(principal,kind,operation))
