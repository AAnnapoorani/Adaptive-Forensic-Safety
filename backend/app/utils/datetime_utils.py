from datetime import datetime, timezone

def to_iso_utc(dt: datetime | None) -> str | None:
    """Format a datetime to standard ISO 8601 string with explicit UTC 'Z' timezone."""
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt if dt.endswith("Z") or "+" in dt else f"{dt}Z"
    
    # If naive, assume UTC as per project convention
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
        
    iso = dt.isoformat()
    # Replace +00:00 with Z for clean standard representation
    if iso.endswith("+00:00"):
        iso = iso[:-6] + "Z"
    return iso
