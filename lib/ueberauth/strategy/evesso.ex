defmodule Ueberauth.Strategy.EVESSO do

  use Ueberauth.Strategy,
    uid_field: :id,
    default_scope: "",
    oauth2_module: Ueberauth.Strategy.EVESSO.Oauth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
end
