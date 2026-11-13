"""PostgreSQL implementation of the trusted membership lookup API."""
import uuid
from sqlalchemy import and_, select, text
from acl_service.infrastructure.atomic import store_session
from controlplane_db.models import Group, User, UserGroupMembership


class PostgresMembershipReader:
    def __init__(self, engine):
        self._engine = engine

    def user_in_group(
        self, tenant_id: uuid.UUID, subject: str, group_id: uuid.UUID
    ) -> bool:
        with store_session(self._engine) as session:
            session.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": str(tenant_id)},
            )
            row = session.scalars(
                select(UserGroupMembership).join(User, User.id == UserGroupMembership.user_id).join(
                    Group, Group.id == UserGroupMembership.group_id
                ).where(
                    and_(
                        UserGroupMembership.tenant_id == tenant_id,
                        User.tenant_id == tenant_id,
                        Group.tenant_id == tenant_id,
                        User.keycloak_sub == subject,
                        User.is_active.is_(True),
                        User.deleted_at.is_(None),
                        UserGroupMembership.group_id == group_id,
                    )
                )
            ).first()
            return row is not None
