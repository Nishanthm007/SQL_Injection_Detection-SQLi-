import numpy as np

def sanitize_json(obj):
    if isinstance(obj, (np.ndarray,)):
        return obj.tolist()
    if isinstance(obj, bytes):
        return obj.decode(errors="replace")
    if isinstance(obj, dict):
        return {k: sanitize_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_json(v) for v in obj]
    return obj
