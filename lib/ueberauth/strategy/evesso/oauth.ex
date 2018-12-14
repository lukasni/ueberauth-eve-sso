defmodule Ueberauth.Strategy.EVESSO.Oauth do
  @moduledoc """
  Implements OAuth2 for EVE SSO v2 with JWT
  
  Include your `client_id` and `secret_key` in your config:
  
  ```elixir
  config :ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
    client_id: System.get_env("EVE_SSO_CLIENT_ID"),
    client_secret: System.get_env("EVE_SSO_CLIENT_SECRET")
  ```
  
  See the [EVE Developer Page](https://developers.eveonline.com) for more details on obtaining a client id.
  """
  use OAuth2.Strategy
  
  @defaults [
    strategy: __MODULE__,
    site: "https://login.eveonline.com",
    authorize_url: "https://login.eveonline.com/v2/oauth/authorize",
    token_url: "https://login.eveonline.com/v2/oauth/token",
  ]
end
