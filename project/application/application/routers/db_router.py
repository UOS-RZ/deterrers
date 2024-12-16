
# Database Router to sort models defined in scan_models into scan_model_db and all other models into the default Database
class Scan_modelRouter:

    labels = {'scan_model'}

    def db_for_read(self, model, **hints):
        if model._meta.app_label in self.labels:
            return 'scan_model_db'
        return 'default'
    
    def db_for_write(self,model, **hints):
        if model._meta.app_label in self.labels:
            return 'scan_model_db'
        return 'default'
    
    def allow_relation(self, obj1,obj2, **hints):
        return None
    
    def allow_migrate(self,scan_model_db,app_label, model_name=None, **hints):
        if app_label in self.labels:
            return scan_model_db == 'scan_model_db'
        return scan_model_db == 'default'