import sys
import uuid

with open("scripts/conf.dat", 'w') as f:
    f.write("eZeeKonfigurator::server_endpoint\t%s/client_api/v1/%s/\n" % (sys.argv[1], uuid.uuid4()))
