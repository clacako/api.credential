import string
import random
import secrets

class Alphanumeric():
    def __init__(self, model=None, *args, **kwargs):
        self.__model    = model
            
    def auto_generate(self):
        length          = 9
        chars           = string.digits
        external_id     = ''.join(random.choice(chars) for _ in range(length))
        if self.__model is not None:
            if self.__model.objects.filter(external_id=external_id).exists():
                Alphanumeric(model=self.__model).auto_generate()
            else:
                return external_id
        
        return external_id

class Generate():
    __length    = 10
    
    def __init__(self, length=None, auto_generate=True):
        self.__length   = length
    
    def run(self):
        return secrets.token_urlsafe(self.__length)