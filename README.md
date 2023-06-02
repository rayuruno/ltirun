# ltirun

```
# dynamic registration endpoint
lti.run/connect.$provider_url
  # fetch platform config
  platform = GET openid_configuration
  # fetch provider config (if exists)
  provider = GET $provider_url/lti/.well-known/openid_configuration
  # proxify provider config
  tool = PROXY provider
  # post proxy tool config
  consumer = POST platform.registration_endpoint tool
  # store registered tool consumer and platform
  RSET $provider_url/platform.iss/consumer.client_id/consumer.deployment_id consumer,platform
  # add jwk
  key = GEN_KEY $provider_url/consumer,platform
  KADD $provider_url key

# jwks endpoint
lti.run/jwks.$provider_url
  jwks = KALL $provider_url
  SEND jwks

# lti advantage platform initiated message launch
# 1. login endpoint
lti.run/login.$provider_url
  # authenticate login request with registry
  consumer = AUTHN $provider_url/$login.iss/$login.client_id/$login.deployment_id
  # sign login state (session)
  state = SIGN consumer $login
  # request auth
  AUTHR state

# 2. launch endpoint
lti.run/launch.$provider_url
  # authorize login state (sessoin)
  login = AUTHZ $state
  # find consumer in registry
  consumer = RGET $provider_url/login.iss/login.client_id/login.deployment_id
  # verify signature
  msg = VERIFY consumer $id_token
  # post decoded request to provider
  link = POST provider msg
  # add jwk
  key = GEN_KEY $provider_url/consumer,msg
  KADD $provider_url key
  # start local session
  SESSION start <- consumer,msg
  # launch target link in iframe
  RENDER tool,link
# TOOL frontend
  LISTEN_MSG provider -service_request-> REQUEST lti.run/service.$provider_url
  LISTEN_MSG tool <-service_response- RESPONSE lti.run/service.$provider_url

# service endpoint
lti.run/service.$provider_url
  consumer, msg = SESSION retrive
  key = KGET $provider_url/consumer,msgr
  request = AUTH_TOKEN_REQUEST key,consumer,msg
  token = POST platform request

  response = POST platform/service $service_request
  SEND response
```
