from django.db.models import ManyToManyField
from django.db.models import ForeignKey

class RequestData():
    def __init__(self, data, validators=None, relation=False, fields=None, models=None):
        self.__data         = data
        self.__validators   = validators
        self.__relation     = relation
        self.__fields       = fields
        self.__model        = models
        
    def is_valid(self):
        for validator in self.__validators:
            if validator not in self.__data:
                self.message      = "Required request data: {}".format(validator)
                return False

        # Cleaning data
        # self.cleaned_data    = {}
        # for key, value in self.__data.items():
        #     self.cleaned_data[key]   = value

        # results = []
        
        """
            Updated at 11 September 2022
        """
        self.cleaned_data   = {**self.__data.dict()} # Copying data
        if self.__relation:
            for key, value in self.__data.items():
                # ManyToMany set the cleaned data value into a list
                if isinstance(self.__model._meta.get_field(key), ManyToManyField):
                    self.cleaned_data[key] = [self.__model._meta.get_field(key).related_model.objects.filter(external_id__in=[self.__data[key]]).first().id]

                # ForeignKey set the cleaned data value into an int
                if isinstance(self.__model._meta.get_field(key), ForeignKey):
                    self.cleaned_data[key] = self.__model._meta.get_field(key).related_model.objects.filter(external_id__in=[self.__data[key]]).first().id
            
            # for index in range(0, len(self.__fields)):
            #     if self.__fields[index] not in self.cleaned_data:
            #         continue
                
            #     # Many to many
            #     if isinstance(self.__models._meta.get_field(self.__fields[index]), ManyToManyField):
            #         results.append([value.id for value in self.__models._meta.get_field(self.__fields[index]).related_model.objects.filter(external_id__in=[self.cleaned_data[self.__fields[index]]])])
            #         self.cleaned_data[self.__fields[index]] = []
                    
            #     # Foreign key
            #     if isinstance(self.__models._meta.get_field(self.__fields[index]), ForeignKey):
            #         results.append(self.__models._meta.get_field(self.__fields[index]).related_model.objects.filter(external_id=self.cleaned_data[self.__fields[index]]).first().id)

            #     self.cleaned_data[self.__fields[index]] = results[index]
        
        return True
    
class QueryParam():
    def __init__(self, model, data, relation=False, *args, **kwargs):
        self.__relation = relation
        self.__model    = model
        self.__data     = data
        
    def is_valid(self):
        # Split data between auth and fields
        parameters  = self.__data.dict()
        fields      = {}
        for key, value in parameters.items():
            if key == "auth": continue
            fields[key]    = value
        
        # Validate that field match with fields from database
        try:
            for field, value in fields.items():
                self.__model._meta.get_field(field)
        except:
            self.error  = f"{field}, not match with the model fields"
            return False
        else:
            self.cleaned_data   = {**fields} # Copying data
            if self.__relation:
                for field, value in fields.items():
                    # Check the fields has a relation
                    if isinstance(self.__model._meta.get_field(field), ManyToManyField) or isinstance(self.__model._meta.get_field(field), ForeignKey):
                        self.cleaned_data[field] = self.__model._meta.get_field(field).related_model.objects.filter(external_id__in=[fields[field]]).first()
                    
            return True

