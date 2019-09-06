from eZeeKonfigurator.settings.common import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'mysecretkey'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['0.0.0.0', 'localhost']

# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'mydatabase',
        'USER': 'mydatabaseuser',
        'PASSWORD': 'mypassword',
        'HOST': '127.0.0.1',
        'PORT': '5432',
    }
}

STATIC_ROOT = 'mystaticroot'

STATIC_URL = '/webconfig/static/'
