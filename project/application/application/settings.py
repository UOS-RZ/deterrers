"""
Django settings for application project.

Generated by 'django-admin startproject' using Django 4.1.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""
import os
from pathlib import Path
import ssl

# domain name of machine that runs the service
DOMAIN_NAME = os.environ.get('DOMAIN_NAME', 'localhost')

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
# second parameter is a default key which is only for development
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'UNSAFE_SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DJANGO_DEBUG', '') == 'True'

# parse dev flags
DEV_MODE = os.environ.get('DEV_MODE', '') == 'True'
IPAM_DUMMY = os.environ.get('IPAM_DUMMY', 'True') == 'True'
SCANNER_DUMMY = os.environ.get('SCANNER_DUMMY', 'True') == 'True'
FIREWALL_TYPE = os.environ.get('FIREWALL_TYPE', 'DUMMY')
SMTP_DUMMY = os.environ.get('SMTP_DUMMY', 'True') == 'True'
USE_LDAP = os.environ.get('USE_LDAP', 'False') == 'True'

WSGI_APPLICATION = 'application.wsgi.application'

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, "static")


""" SETUP HTTP SECURITY CONFIGS """

# security configurations for productive deployment
if not DEV_MODE:
    SECURE_HSTS_SECONDS = 3600
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

# 'DJANGO_ALLOWED_HOSTS' should be a single string of hosts with a space
# between each.
# For example: 'DJANGO_ALLOWED_HOSTS=localhost 127.0.0.1 [::1]'
ALLOWED_HOSTS = os.environ.get(
    "DJANGO_ALLOWED_HOSTS",
    "localhost 127.0.0.1 0.0.0.0 [::1]"
).split(" ")

CSRF_TRUSTED_ORIGINS = os.environ.get(
    "CSRF_TRUSTED_ORIGINS", "https://*.127.0.0.1 http://*.127.0.0.1"
).split(' ')


""" SETUP LOGGING """

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    'formatters': {
        'verbose': {
            'format': ('{levelname} {asctime} {module} {process:d} '
                       + '{thread:d} {message}'),
            'style': '{',
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "web_app_log_file": {
            "class": "logging.handlers.WatchedFileHandler",
            "filename": os.path.join(
                    os.environ.get(
                        'MICRO_SERVICE',
                        BASE_DIR.parent
                    ), "logs/deterrers-app.log"
                ),
            "formatter": "verbose",
        },
    },
    "loggers": {
        "": {
            "handlers": ["web_app_log_file", "console"],
            "level": os.environ.get('LOG_LEVEL', 'INFO'),
            'propagate': True,
        },
        "django_python3_ldap": {
            "handlers": ["web_app_log_file", "console"],
            "level": 'WARNING',
        },
    },
}


""" SETUP APPLICATION DEFINITION """

INSTALLED_APPS = [
    'django.contrib.admin',                 # useful
    'django.contrib.auth',                  # needed
    'django.contrib.contenttypes',
    'django.contrib.sessions',              # needed
    'django.contrib.messages',              # needed
    'django.contrib.staticfiles',           # needed
    # Third-party applications
    'django_python3_ldap',
    'django_bootstrap5',
    'rest_framework',
    'rest_framework.authtoken',
    'maintenance_mode',
    # Custom applications
    'main.apps.MainConfig',
    'user.apps.UserConfig',
    'vulnerability_mgmt.apps.VulnerabilityMgmtConfig'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'maintenance_mode.middleware.MaintenanceModeMiddleware'
]

# e-mail configuration
if SMTP_DUMMY:
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
else:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    DEFAULT_FROM_EMAIL = os.environ.get(
        'DEFAULT_EMAIL_FROM',
        'no-reply@example.de'
    )
    EMAIL_HOST = os.environ.get('SMTP_URL', 'localhost')
    EMAIL_PORT = os.environ.get('SMTP_PORT', 25)
    EMAIL_HOST_USER = os.environ.get('SMTP_USERNAME', '')
    EMAIL_HOST_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    # EMAIL_USE_SSL = False
    EMAIL_USE_TLS = True

ROOT_URLCONF = 'application.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates'), ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',     # noqa: E501
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',   # noqa: E501
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',  # noqa: E501
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',     # noqa: E501
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Europe/Berlin'
USE_I18N = True
USE_TZ = True


""" SETUP DATABASE """

# Get Postgresql configuration
POSTGRESQL_USER = os.environ.get('POSTGRES_USER', '')
POSTGRESQL_PASSWORD = os.environ.get('POSTGRES_PASSWORD', '')
POSTGRESQL_HOST = os.environ.get('POSTGRES_HOST', '')
POSTGRESQL_PORT = os.environ.get('POSTGRES_PORT', '')
POSTGRESQL_VULNERABILITY_MGMT_DB = os.environ.get('POSTGRES_DB', '')
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': "default",
        'USER': POSTGRESQL_USER,
        'PASSWORD': POSTGRESQL_PASSWORD,
        'HOST': 'default',
        'PORT': POSTGRESQL_PORT,

    },
    'vulnerability_mgmt': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': POSTGRESQL_VULNERABILITY_MGMT_DB,
        'USER': POSTGRESQL_USER,
        'PASSWORD': POSTGRESQL_PASSWORD,
        'HOST': POSTGRESQL_HOST,
        'PORT': POSTGRESQL_PORT,

    }
}
# Specify the Database Routers
DATABASE_ROUTERS = ['application.routers.db_router.DatabaseRouter']

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


""" SETUP LDAP AUTHENTICATION """

if USE_LDAP:
    AUTHENTICATION_BACKENDS = [
        "django_python3_ldap.auth.LDAPBackend",
        'django.contrib.auth.backends.ModelBackend',
    ]
    LDAP_AUTH_URL = os.environ.get("LDAP_AUTH_URL", " ").split(' ')
    LDAP_AUTH_USE_TLS = True
    LDAP_AUTH_TLS_VERSION = ssl.PROTOCOL_TLSv1_2
    LDAP_AUTH_SEARCH_BASE = os.environ.get("LDAP_AUTH_SEARCH_BASE", "")
    LDAP_AUTH_USER_FIELDS = {
        "username": "uid",
        "first_name": "givenName",
        "last_name": "sn",
        "email": "mail",
    }
    LDAP_AUTH_USER_LOOKUP_FIELDS = ("username",)
    # The LDAP username and password of a user for querying the LDAP database
    # for user details. If None, then the authenticated user will be used for
    # querying, and the `ldap_sync_users`, `ldap_clean_users` commands will
    # perform an anonymous query.
    LDAP_AUTH_CONNECTION_USERNAME = None
    LDAP_AUTH_CONNECTION_PASSWORD = None
    # Set connection/receive timeouts (in seconds) on the underlying `ldap3`
    # library.
    LDAP_AUTH_CONNECT_TIMEOUT = None
    LDAP_AUTH_RECEIVE_TIMEOUT = None
else:
    AUTHENTICATION_BACKENDS = [
        'django.contrib.auth.backends.ModelBackend',
    ]

LOGIN_URL = '/login/'

# Redirect to home URL after login
LOGIN_REDIRECT_URL = '/'

# Redirect to login after logout
LOGOUT_REDIRECT_URL = '/login/'

AUTH_USER_MODEL = 'user.MyUser'


""" SETUP MAINTENANCE MODE """

MAINTENANCE_MODE = os.environ.get('MAINTENANCE_MODE', '') == 'True'
# if True admin site will not be affected by the maintenance-mode page
MAINTENANCE_MODE_IGNORE_ADMIN_SITE = True
# if True the superuser will not see the maintenance-mode page
MAINTENANCE_MODE_IGNORE_SUPERUSER = True
# list of urls that will not be affected by the maintenance-mode
# urls will be used to compile regular expressions objects
MAINTENANCE_MODE_IGNORE_URLS = (
    LOGIN_URL,
    '/hostadmin/scanner/'
)
# retry after
MAINTENANCE_MODE_RETRY_AFTER = 3600


""" SETUP APP CONFIG """

# get all secret keys for APIs etc.
IPAM_URL = os.environ.get('IPAM_URL', '')
IPAM_USERNAME = os.environ.get('IPAM_USERNAME', '')
IPAM_SECRET_KEY = os.environ.get('IPAM_SECRET_KEY', '')

SCANNER_HOSTNAME = os.environ.get('SCANNER_HOSTNAME', '')
SCANNER_USERNAME = os.environ.get('SCANNER_USERNAME', '')
SCANNER_SECRET_KEY = os.environ.get('SCANNER_SECRET_KEY', '')

FIREWALL_URL = os.environ.get('FIREWALL_URL', '')
FIREWALL_USERNAME = os.environ.get('FIREWALL_USERNAME', '')
FIREWALL_SECRET_KEY = os.environ.get('FIREWALL_SECRET_KEY', '')

DJANGO_SUPERUSER_USERNAME = os.environ.get('DJANGO_SUPERUSER_USERNAME', '')
DJANGO_SUPERUSER_EMAIL = os.environ.get('DJANGO_SUPERUSER_EMAIL', '')

# Risk assessment thresholds
REGI_HIGH_CVSS_T = float(os.environ.get("REGI_HIGH_CVSS_T", 8.5))
REGI_MEDIUM_CVSS_T = float(os.environ.get("REGI_MEDIUM_CVSS_T", 5.0))
PERIO_HIGH_CVSS_T = float(os.environ.get("PERIO_HIGH_CVSS_T", 8.5))
PERIO_MEDIUM_CVSS_T = float(os.environ.get("PERIO_MEDIUM_CVSS_T", 6.0))

# get deployment identifier
DEPLOYMENT_UNIQUE_IDENTIFIER = os.environ.get(
    'DEPLOYMENT_UNIQUE_IDENTIFIER',
    'Unknown'
)

RZ_INTERN_RANGES = os.environ.get('RZ_INTERN_RANGES', '').split()
VM_INTERN_RANGES = os.environ.get('VM_INTERN_RANGES', '').split()
IT_ADMIN_VPN_RANGES = os.environ.get('IT_ADMIN_VPN_RANGES', '').split()
