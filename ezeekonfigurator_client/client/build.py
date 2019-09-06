import os
import sys
import uuid

url = sys.argv[1]
install_dir = sys.argv[2]
conf = os.path.join(install_dir, "ezeekonfigurator_client", "conf.dat")

with open("scripts/conf.dat", 'w') as f:
    if os.path.exists(conf) and os.path.isfile(conf):
        f.write(open(conf).read())
    else:
        f.write("eZeeKonfigurator::server_endpoint\t%s/client_api/v1/%s/\n" % (url, uuid.uuid4()))

