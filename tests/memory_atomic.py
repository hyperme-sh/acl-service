"""Explicit in-memory transaction substitute for route and consumer unit tests."""
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
import uuid


class MemoryOperation:
    def __init__(self,store,events,inbox):
        self.store=store;self.events=events;self.inbox=inbox;self.connection=self
    def lock(self,key):pass
    def execute(self,statement,params=None):
        result=None;sql=str(statement)
        if sql.startswith('INSERT INTO event_inbox'):
            if params['id'] not in self.inbox:
                self.inbox[params['id']]=params['envelope'];result=params['id']
        elif sql.startswith('SELECT envelope FROM event_inbox'):result=self.inbox.get(params['id'])
        return SimpleNamespace(scalar_one_or_none=lambda:result)
    def emit(self,**event):
        event_id=uuid.uuid5(uuid.NAMESPACE_URL,str(event['tenant_id'])+event['event_type']+event['operation_id'])
        if event_id in self.events and self.events[event_id]!=event:raise ValueError('Conflicting repeat')
        self.events[event_id]=event
        return event_id


def install(store,*,fail=False):
    events={};inbox={}
    @contextmanager
    def atomic():
        before=deepcopy(getattr(store,'rows',{})),deepcopy(events),deepcopy(inbox)
        op=MemoryOperation(store,events,inbox)
        if fail:
            def refuse(**kwargs):raise RuntimeError('outbox refused')
            op.emit=refuse
        try:yield op
        except BaseException:
            store.rows=before[0];events.clear();events.update(before[1]);inbox.clear();inbox.update(before[2]);raise
    store.atomic=atomic
    return events,inbox
