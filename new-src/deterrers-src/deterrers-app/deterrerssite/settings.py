"""
Django settings for deterrerssite project.

Generated by 'django-admin startproject' using Django 4.1.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""

import os
from pathlib import Path

DOMAIN_NAME = os.environ.get('DOMAIN_NAME', 'vm305.rz.uos.de')


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# second parameter is a default key which is only for development
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'NON_SECRET_DEV_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
# DEBUG = True
DEBUG = os.environ.get('DJANGO_DEBUG', '') != 'False'

# 'DJANGO_ALLOWED_HOSTS' should be a single string of hosts with a space between each.
# For example: 'DJANGO_ALLOWED_HOSTS=localhost 127.0.0.1 [::1]'
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost 127.0.0.1 0.0.0.0 [::1]").split(" ")

CSRF_TRUSTED_ORIGINS = [
    'https://deterrers.rz.uni-osnabrueck.de',
    'http://deterrers.rz.uni-osnabrueck.de',
    'https://deterrers.rz.uos.de',
    'http://deterrers.rz.uos.de',
    'https://vm305.rz.uos.de',
    'http://vm305.rz.uos.de',
    'https://vm305.rz.uni-osnabrueck.de',
    'http://vm305.rz.uni-osnabrueck.de',
    'https://*.127.0.0.1',
    'http://*.127.0.0.1'
]

# more extensive logging
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "web_app_log_file": {
            "class": "logging.FileHandler",
            "filename": os.path.join(os.environ.get('MICRO_SERVICE', BASE_DIR), "logs/deterrers-app.log"),
            "formatter": "verbose",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["web_app_log_file", "console"],
            "level": os.environ.get('LOG_LEVEL', 'INFO'),
            'propagate': True,
        },
        "django_python3_ldap": {
            "handlers": ["console"],
            "level": 'WARNING', # os.environ.get('LOG_LEVEL', 'WARNING'),
        },
    },
    # 'root': {
    #     'handlers': ['console'],
    #     'level': 'WARNING', # os.environ.get('LOG_LEVEL', 'INFO'),
    # },
}


# Application definition

# TODO: clean up for production
INSTALLED_APPS = [
    'django.contrib.admin',                 # useful
    'django.contrib.auth',                  # needed
    'django.contrib.contenttypes',          
    'django.contrib.sessions',              # needed
    'django.contrib.messages',              # needed
    'django.contrib.staticfiles',           # needed
    # Custom applications
    'hostadmin.apps.HostadminConfig',
    'myuser.apps.MyuserConfig',
    # Third-party applications
    'django_python3_ldap',
    'django_bootstrap5',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# e-mail configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend' # 'django.core.mail.backends.console.EmailBackend'
DEFAULT_FROM_EMAIL = f'noreply@{DOMAIN_NAME}'
EMAIL_HOST = os.environ.get('SMTP_URL', 'localhost')
EMAIL_PORT = os.environ.get('SMTP_PORT', 25)
EMAIL_HOST_USER = os.environ.get('SMTP_USERNAME', '')
EMAIL_HOST_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
# EMAIL_USE_SSL = False
EMAIL_USE_TLS = True


ROOT_URLCONF = 'deterrerssite.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates'),],
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

WSGI_APPLICATION = 'deterrerssite.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(os.environ.get('MICRO_SERVICE', BASE_DIR), 'db/db.sqlite3'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Europe/Berlin'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = '/static/'

STATIC_ROOT = os.path.join(BASE_DIR, "static")

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# Redirect to home URL after login (Default redirects to /accounts/profile/)
LOGIN_REDIRECT_URL = '/'

AUTH_USER_MODEL = 'myuser.MyUser'


# Setup for LDAP Authentication

AUTHENTICATION_BACKENDS = [
    "django_python3_ldap.auth.LDAPBackend",
    'django.contrib.auth.backends.ModelBackend',
]

LDAP_AUTH_URL = ["ldap://ldap.uni-osnabrueck.de"]

LDAP_AUTH_USE_TLS = True

import ssl
LDAP_AUTH_TLS_VERSION = ssl.PROTOCOL_TLSv1_2

LDAP_AUTH_SEARCH_BASE = "ou=people,dc=uni-osnabrueck,dc=de"

LDAP_AUTH_USER_FIELDS = {
    "username": "uid",
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail",
}

LDAP_AUTH_USER_LOOKUP_FIELDS = ("username",)

# The LDAP username and password of a user for querying the LDAP database for user
# details. If None, then the authenticated user will be used for querying, and
# the `ldap_sync_users`, `ldap_clean_users` commands will perform an anonymous query.
LDAP_AUTH_CONNECTION_USERNAME = None
LDAP_AUTH_CONNECTION_PASSWORD = None

# Set connection/receive timeouts (in seconds) on the underlying `ldap3` library.
LDAP_AUTH_CONNECT_TIMEOUT = None
LDAP_AUTH_RECEIVE_TIMEOUT = None


LOGIN_URL = '/login/'

# get all secret keys for APIs etc.
IPAM_URL = os.environ.get('IPAM_URL')
IPAM_USERNAME = os.environ.get('IPAM_USERNAME')
IPAM_SECRET_KEY = os.environ.get('IPAM_SECRET_KEY', '')

V_SCANNER_URL = os.environ.get('V_SCANNER_URL')
V_SCANNER_USERNAME = os.environ.get('V_SCANNER_USERNAME')
V_SCANNER_SECRET_KEY = os.environ.get('V_SCANNER_SECRET_KEY', '')

FIREWALL_URL = os.environ.get('FIREWALL_URL')
FIREWALL_USERNAME = os.environ.get('FIREWALL_USERNAME')
FIREWALL_SECRET_KEY = os.environ.get('FIREWALL_SECRET_KEY')
