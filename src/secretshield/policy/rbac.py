"""Role-Based Access Control (RBAC) policy engine for SecretShield."""

import fnmatch
from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field
from secretshield.policy.authenticator import CallerIdentity


class PermissionDeniedError(Exception):
    """Raised when caller lacks permission to invoke target profile or endpoint."""


class PolicyRule(BaseModel):
    """Declarative access rule for a microservice."""
    service_id: str
    allowed_profiles: List[str] = Field(default_factory=lambda: ["*"])
    denied_profiles: List[str] = Field(default_factory=list)
    allowed_methods: List[str] = Field(default_factory=lambda: ["*"])
    denied_methods: List[str] = Field(default_factory=list)
    allowed_paths: List[str] = Field(default_factory=lambda: ["*"])
    denied_paths: List[str] = Field(default_factory=list)


class PolicyEngine:
    """Evaluates service permissions against requested profiles and routes."""

    def __init__(self, default_deny: bool = True):
        self.default_deny = default_deny
        self._rules: Dict[str, PolicyRule] = {}

    def set_rule(self, rule: PolicyRule) -> None:
        """Register or update an access control rule for a service."""
        self._rules[rule.service_id] = rule

    def get_rule(self, service_id: str) -> Optional[PolicyRule]:
        """Retrieve rule for a service."""
        return self._rules.get(service_id)

    def is_allowed(
        self,
        service_id: str,
        profile_name: str,
        method: str,
        path: str,
    ) -> Tuple[bool, str]:
        """Evaluate whether service_id is permitted to access the target.

        Evaluation order:
        1. Look up rule for service_id. If missing and default_deny is True, deny.
        2. Explicit DENY checks (profile, method, path). Deny immediately if matched.
        3. ALLOW checks (profile, method, path). Must match all three categories.

        Returns:
            Tuple of (is_allowed: bool, reason: str).
        """
        rule = self._rules.get(service_id)
        if not rule:
            if self.default_deny:
                return False, f"No policy rule defined for service '{service_id}'"
            return True, "Default allow"

        normalized_method = method.upper()
        normalized_path = "/" + path.lstrip("/")

        # 1. Explicit denials take precedence
        for denied_prof in rule.denied_profiles:
            if fnmatch.fnmatch(profile_name, denied_prof):
                return False, f"Profile '{profile_name}' is explicitly denied"

        for denied_m in rule.denied_methods:
            if fnmatch.fnmatch(normalized_method, denied_m.upper()):
                return False, f"Method '{normalized_method}' is explicitly denied"

        for denied_p in rule.denied_paths:
            if fnmatch.fnmatch(normalized_path, denied_p):
                return False, f"Path '{normalized_path}' is explicitly denied"

        # 2. Check profile allowance
        profile_matched = any(
            fnmatch.fnmatch(profile_name, allowed)
            for allowed in rule.allowed_profiles
        )
        if not profile_matched:
            return False, f"Profile '{profile_name}' is not in allowed list: {rule.allowed_profiles}"

        # 3. Check method allowance
        method_matched = any(
            fnmatch.fnmatch(normalized_method, allowed.upper())
            for allowed in rule.allowed_methods
        )
        if not method_matched:
            return False, f"Method '{normalized_method}' is not in allowed list: {rule.allowed_methods}"

        # 4. Check path allowance
        path_matched = any(
            fnmatch.fnmatch(normalized_path, allowed)
            for allowed in rule.allowed_paths
        )
        if not path_matched:
            return False, f"Path '{normalized_path}' is not in allowed list: {rule.allowed_paths}"

        return True, "Authorized"

    def enforce(
        self,
        caller: CallerIdentity,
        profile_name: str,
        method: str,
        path: str,
    ) -> None:
        """Enforce permissions or raise PermissionDeniedError."""
        allowed, reason = self.is_allowed(
            service_id=caller.service_id,
            profile_name=profile_name,
            method=method,
            path=path,
        )
        if not allowed:
            raise PermissionDeniedError(f"Access denied: {reason}")
