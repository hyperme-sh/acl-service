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


class MembershipOwnerUnavailable(RuntimeError):
    """A membership decision could not be obtained from the User owner."""


class UserOwnerMembershipReader:
    """Read one membership from User with a purpose-scoped credential."""

    def __init__(self, origin: str, token: str):
        from urllib.parse import urlsplit

        url = urlsplit(origin)
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or url.password is not None or url.path not in ("", "/")
                or url.query or url.fragment or not token
                or any(ord(char) < 33 or ord(char) > 126 for char in token)):
            raise ValueError("Private User owner origin and ACL membership credential required")
        self.url = origin.rstrip("/") + "/api/v1/internal/acl/group-membership"
        self._token = token

    def user_in_group(self, tenant_id: uuid.UUID, subject: str, group_id: uuid.UUID) -> bool:
        import httpx

        tenant = str(tenant_id)
        try:
            with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
                response = client.post(
                    self.url,
                    headers={"Authorization": f"Bearer {self._token}", "X-Tenant-ID": tenant},
                    json={"tenant_id": tenant, "subject": subject, "group_id": str(group_id)},
                )
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError):
            raise MembershipOwnerUnavailable("User membership unavailable") from None
        if type(body) is not dict or set(body) != {"member"} or type(body["member"]) is not bool:
            raise MembershipOwnerUnavailable("Unexpected User membership response")
        return body["member"]


def configured_membership_reader(engine):
    import os

    backend = os.environ.get("ACL_MEMBERSHIP_BACKEND", "postgres")
    if backend == "postgres":
        return PostgresMembershipReader(engine)
    if backend == "user-owner":
        return UserOwnerMembershipReader(
            os.environ.get("ACL_MEMBERSHIP_USER_ORIGIN", ""),
            os.environ.get("ACL_MEMBERSHIP_LOOKUP_TOKEN", ""),
        )
    raise ValueError("Unknown ACL membership backend")
