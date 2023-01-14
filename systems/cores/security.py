from django.conf import settings
from cryptography.fernet import Fernet
import hashlib

class ClightCrypto():
    __keys              = None
    __secret_key        = None
    __keys_encrypted    = None
    
    def __init__(self, keys, secret_key):
        self.__keys         = keys
        self.__secret_key   = secret_key
    
    def encrypt(self):
        keys    = [];
        for key in self.__keys:
            key     = str(key)
            fernet  = Fernet(self.__secret_key)
            keys.append(fernet.encrypt(key.encode()).decode("utf-8"))
        
        self.__keys_encrypted   = ".".join(keys)
        return ".".join(keys)
        
    
    def decrypt(self, keys=None):
        fernet  = Fernet(settings.FERNET_SECRET_KEY)
        
        key_split   = self.__keys.split(".")
        keys    = []
        for key in key_split:
            keys.append(
                fernet.decrypt(
                    key.encode()
                ).decode()
            )
        
        return keys
    
class ClightHash():
    __key  = None
    
    def __init__(self, key, *args, **kwargs):
        self.__key = key
            
    def hash_md5(self):
        hash = hashlib.md5("{}{}".format(settings.SECRET_KEY, self.__key).encode('utf-8')).hexdigest()
        
        return hash
    
    def hash_sha256(self):
        hash = hashlib.sha256("{}{}".format(self.__key, settings.SECRET_KEY).encode("utf-8")).hexdigest()

        return hash