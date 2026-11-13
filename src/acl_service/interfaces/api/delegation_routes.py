"""Private same-tenant delegated-agent history transport."""
from uuid import UUID
from fastapi import APIRouter, Depends, Request
from auth_service.schemas import AuthMeResponse
from acl_service.deps import get_current_user, require_matched_tenant
from acl_service.interfaces.api.statement_routes import graph_operation

router = APIRouter(prefix='/acl/sociacl/delegations', tags=['SociACL'])


@router.post('/{scope}/{operation}')
async def delegation_operation(scope: str, operation: str, request: Request,
    tenant: UUID = Depends(require_matched_tenant), user: AuthMeResponse = Depends(get_current_user)):
    return await graph_operation(scope, operation, request, tenant, user,
                                 namespace='delegation', permission_prefix='acl:delegations:')
