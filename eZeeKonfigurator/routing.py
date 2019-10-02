from channels.routing import ProtocolTypeRouter, URLRouter
import webconfig.routing

application = ProtocolTypeRouter({
    'http': URLRouter(webconfig.routing.urlpatterns),
})