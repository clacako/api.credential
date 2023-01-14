from django.utils.html import strip_tags, mark_safe
from datetime import datetime

def json_message(status, message=None, data=[]):
    message     = f"Success at {datetime.now()}" if status == 200 or status == 201 else message
    response    = {
        "status"    : status,
        "message"   : message,
        "data"      : data
    }
    
    return response
    
def serializer_errors_to_str(message):
    errors   = []
    for key, value in message.items():
        errors.append(f"<strong>{key.title()}</strong>, {message.get(key)[0]}")
        
    return " <br /> ".join(errors)