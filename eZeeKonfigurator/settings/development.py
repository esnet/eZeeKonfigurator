from eZeeKonfigurator.settings.common import *

SECRET_KEY = 'dev_(w1ppk=v_=j^m8ogs=76vcz-wz$xf6e@r0=$eerqfib&m)kq0c_dev'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['localhost', 'testserver']

# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, '..', 'db.sqlite3'),
    }
}

STATIC_ROOT = 'static'

STATIC_URL = '/static/'
