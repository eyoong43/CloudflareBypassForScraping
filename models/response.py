from typing import Optional, Dict, Any
from pydantic import BaseModel

class CookieResponse(BaseModel):
    cookies: Dict[str, Dict[str, Any]]
    user_agent: str
    
class TurnstileResponse(BaseModel):
    token: str