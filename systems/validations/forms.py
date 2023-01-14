import re

class PhoneNumber():
    def __init__(self, phone_number, *args, **kwargs):
        phone_number_list   = list(phone_number)
        # self.cleaned_data   = None
        if phone_number_list[0] == '0' and phone_number_list[1] == '8':
            del phone_number_list[0]
            phone_number_list.insert(0, '6')
            phone_number_list.insert(1, '2')
            self.cleaned_data   = ''.join(phone_number_list)
            
        if phone_number_list[0] == '6' and phone_number_list[1] == '2':
            self.cleaned_data   = ''.join(phone_number_list)
            
class SpecialChar():
    def __init__(self, text, *args, **kwargs):
        self.__regex    = re.compile('[@_!#$%^&*()<>?/\ |}""=+{~`:]')
        self.__text     = text
        
    def __result(self):
        result  = re.findall(self.__regex, self.__text)
        return result
    
    def is_valid(self):
        if (self.__regex.search(self.__text) is None):
            return True

        self.not_allowed_chars  = self.__result()
        return False
