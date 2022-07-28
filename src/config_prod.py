import os

from youwol_accounts import Configuration
from youwol_utils import RedisCacheClient, CleanerThread, factory_local_cache
from youwol_utils.clients.oidc.oidc_config import PrivateClient, OidcInfos
from youwol_utils.context import DeployedContextReporter
from youwol_utils.middlewares import AuthMiddleware
from youwol_utils.middlewares import JwtProviderCookie, JwtProviderBearer
from youwol_utils.servers.env import REDIS, KEYCLOAK_ADMIN, OPENID_CLIENT, Env
from youwol_utils.servers.fast_api import AppConfiguration, ServerOptions, FastApiMiddleware


async def get_configuration():
    required_env_vars = OPENID_CLIENT + REDIS + KEYCLOAK_ADMIN

    not_founds = [v for v in required_env_vars if not os.getenv(v)]
    if not_founds:
        raise RuntimeError(f"Missing environments variable: {not_founds}")

    openid_base_url = os.getenv(Env.OPENID_BASE_URL)
    openid_client_id = os.getenv(Env.OPENID_CLIENT_ID)
    openid_client_secret = os.getenv(Env.OPENID_CLIENT_SECRET)
    openid_infos = OidcInfos(base_uri=openid_base_url,
                             client=PrivateClient(
                                 client_id=openid_client_id,
                                 client_secret=openid_client_secret)
                             )
    keycloak_admin_base_url = os.getenv(Env.KEYCLOAK_ADMIN_BASE_URL)
    keycloak_admin_client_id = os.getenv(Env.KEYCLOAK_ADMIN_CLIENT_ID)
    keycloak_admin_client_secret = os.getenv(Env.KEYCLOAK_ADMIN_CLIENT_SECRET)

    redis_host = os.getenv(Env.REDIS_HOST)
    jwt_cache = RedisCacheClient(host=redis_host, prefix='jwt_cache')

    cleaner_thread = CleanerThread()
    pkce_cache = factory_local_cache(cleaner_thread, 'pkce_cache')

    async def on_before_startup():
        try:
            cleaner_thread.go()
        except BaseException as e:
            print("Error while starting download thread")
            raise e

    service_config = Configuration(
        openid_client=PrivateClient(client_id=openid_client_id, client_secret=openid_client_secret),
        openid_base_url=openid_base_url,
        admin_client=PrivateClient(client_id=keycloak_admin_client_id, client_secret=keycloak_admin_client_secret),
        keycloak_admin_base_url=keycloak_admin_base_url,
        jwt_cache=jwt_cache,
        pkce_cache=pkce_cache
    )

    server_options = ServerOptions(
        root_path='/api/accounts',
        http_port=8080,
        base_path="",
        middlewares=[
            FastApiMiddleware(
                AuthMiddleware, {
                    'openid_infos': openid_infos,
                    'predicate_public_path': lambda url:
                    url.path.endswith("/healthz") or url.path.startswith("/api/accounts/openid_rp/"),
                    'jwt_providers': [JwtProviderBearer(),
                                      JwtProviderCookie(
                                          jwt_cache=jwt_cache,
                                          openid_infos=openid_infos
                                      )],
                }
            )

        ],
        ctx_logger=DeployedContextReporter(),
        on_before_startup=on_before_startup
    )
    return AppConfiguration(
        server=server_options,
        service=service_config
    )
