# Database Router to sort models defined in vulnerability_mgmt into
# vulnerability_mgmt and all other models into the default Database
class DatabaseRouter:

    labels = {'vulnerability_mgmt'}

    def db_for_read(self, model, **hints):
        if model._meta.app_label in self.labels:
            return 'vulnerability_mgmt'
        return 'default'

    def db_for_write(self, model, **hints):
        if model._meta.app_label in self.labels:
            return 'vulnerability_mgmt'
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        return None

    def allow_migrate(
            self,
            scan_model_db,
            app_label,
            model_name=None,
            **hints
              ):
        if app_label in self.labels:
            return scan_model_db == 'vulnerability_mgmt'
        return scan_model_db == 'default'
