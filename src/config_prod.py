import os

from youwol.backends.accounts import Configuration
from youwol.utils import RedisCacheClient
from youwol.utils.clients.oidc.oidc_config import PrivateClient, OidcInfos
from youwol.utils.context import DeployedContextReporter
from youwol.utils.middlewares import AuthMiddleware
from youwol.utils.middlewares import JwtProviderCookie, JwtProviderBearer
from youwol.utils.servers.env import REDIS, KEYCLOAK_ADMIN, OPENID_CLIENT, Env
from youwol.utils.servers.fast_api import (
    AppConfiguration,
    ServerOptions,
    FastApiMiddleware,
)


async def get_configuration():
    required_env_vars = OPENID_CLIENT + REDIS + KEYCLOAK_ADMIN

    not_founds = [v for v in required_env_vars if not os.getenv(v)]
    if not_founds:
        raise RuntimeError(f"Missing environments variable: {not_founds}")

    openid_base_url = os.getenv(Env.OPENID_BASE_URL)
    openid_client_id = os.getenv(Env.OPENID_CLIENT_ID)
    openid_client_secret = os.getenv(Env.OPENID_CLIENT_SECRET)
    openid_infos = OidcInfos(
        base_uri=openid_base_url,
        client=PrivateClient(
            client_id=openid_client_id, client_secret=openid_client_secret
        ),
    )
    keycloak_admin_base_url = os.getenv(Env.KEYCLOAK_ADMIN_BASE_URL)
    keycloak_admin_client_id = os.getenv(Env.KEYCLOAK_ADMIN_CLIENT_ID)
    keycloak_admin_client_secret = os.getenv(Env.KEYCLOAK_ADMIN_CLIENT_SECRET)

    redis_host = os.getenv(Env.REDIS_HOST)
    auth_cache = RedisCacheClient(host=redis_host, prefix="auth_cache")

    service_config = Configuration(
        openid_client=PrivateClient(
            client_id=openid_client_id, client_secret=openid_client_secret
        ),
        openid_base_url=openid_base_url,
        admin_client=PrivateClient(
            client_id=keycloak_admin_client_id,
            client_secret=keycloak_admin_client_secret,
        ),
        keycloak_admin_base_url=keycloak_admin_base_url,
        auth_cache=auth_cache,
    )

    server_options = ServerOptions(
        root_path="/api/accounts",
        http_port=8080,
        base_path="",
        middlewares=[
            FastApiMiddleware(
                AuthMiddleware,
                {
                    "openid_base_uri": openid_base_url,
                    "predicate_public_path": lambda url: url.path.endswith("/healthz")
                    or url.path.startswith("/api/accounts/openid_rp/"),
                    "jwt_providers": [
                        JwtProviderBearer(),
                        JwtProviderCookie(
                            auth_cache=auth_cache, openid_infos=openid_infos
                        ),
                    ],
                },
            )
        ],
        ctx_logger=DeployedContextReporter(),
    )
    return AppConfiguration(server=server_options, service=service_config)
