FROM centos:8 AS ezk

ENV CI yes
ENV DJANGO_SETTINGS_MODULE eZeeKonfigurator.settings.development

RUN yum install -y python36-devel python36 sqlite

COPY . /app
WORKDIR /app

RUN python3 -m venv venv
RUN venv/bin/python -m pip install --upgrade pip setuptools wheel
RUN venv/bin/python3 setup.py install

RUN venv/bin/python3 manage.py migrate

CMD ["venv/bin/python3", "manage.py", "runserver", "0.0.0.0:8000"]

FROM ezk as ezk_test

# With Zeek and Firefox

RUN curl https://download.opensuse.org/repositories/security:/zeek/CentOS_8/security:zeek.repo \
    -o /etc/yum.repos.d/zeek.repo && \
    yum install -y zeekctl firefox

ENV PATH /opt/zeek/bin:${PATH}

RUN curl -L -O https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz
RUN tar xf geckodriver-v0.24.0-linux64.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/geckodriver

