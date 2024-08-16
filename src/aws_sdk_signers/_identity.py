"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
"""

import sys
from dataclasses import dataclass
from datetime import datetime, timezone

from .interfaces.identity import Identity

if sys.version_info < (3, 12):
    from datetime import timezone

    UTC = timezone.utc
else:
    from datetime import UTC


@dataclass(kw_only=True)
class AWSCredentialIdentity(Identity):
    access_key_id: str
    secret_access_key: str
    session_token: str | None = None
    expiration: datetime | None = None

    @property
    def is_expired(self) -> bool:
        """Whether the identity is expired."""
        if self.expiration is None:
            return False
        return self.expiration < datetime.now(UTC)
