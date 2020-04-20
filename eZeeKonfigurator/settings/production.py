from eZeeKonfigurator.settings.common import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'mysecretkey'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

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
        'ATOMIC_REQUESTS': True,
    }
}

# The path to where the static files should be installed. Your webserver should be configured to serve these files.
STATIC_ROOT = 'mystaticroot'

# If installing under a different path than /, set the following. No trailing slash.
FORCE_SCRIPT_NAME = ''

# The URL that will serve up the files
STATIC_URL = FORCE_SCRIPT_NAME + '/webconfig/static/'
