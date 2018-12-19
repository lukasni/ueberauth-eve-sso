use Mix.Config

config :ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
  client_id: System.get_env("EVE_SSO_CLIENT_ID"),
  client_secret: System.get_env("EVE_SSO_CLIENT_SECRET")

config :oauth2,
  serializers: %{
    "application/json" => Jason
  }
