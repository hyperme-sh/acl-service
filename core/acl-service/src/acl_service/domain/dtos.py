from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class PolicyRuleCreate(BaseModel):
    """One Casbin policy row: ptype + values mapped to v0..v5."""

    ptype: str = Field(..., min_length=1, max_length=64)
    rule: list[str] = Field(..., min_length=1, max_length=6)


class PolicyRuleDelete(BaseModel):
    ptype: str = Field(..., min_length=1, max_length=64)
    rule: list[str] = Field(..., min_length=1, max_length=6)


class PolicyRowResponse(BaseModel):
    id: int
    ptype: str | None
    v0: str | None
    v1: str | None
    v2: str | None
    v3: str | None
    v4: str | None
    v5: str | None


class EnforceRequest(BaseModel):
    model: Literal["rbac", "abac"] = "rbac"
    sub: str = Field(..., min_length=1, max_length=512)
    obj: str = Field(..., min_length=1, max_length=512)
    act: str = Field(..., min_length=1, max_length=128)
    extra: str | None = Field(
        default=None,
        max_length=128,
        description="4th request field for ABAC model (e.g. political_view category)",
    )


class EnforceResponse(BaseModel):
    allow: bool
