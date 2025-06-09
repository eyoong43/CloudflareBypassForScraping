from typing import Optional, Dict
from pydantic import BaseModel

class CloudflareRequest(BaseModel):
    url: str
    retries: int = 5
    proxy: Optional[str] = None
    client_key: Optional[str] = None
    site_key: Optional[str] = None