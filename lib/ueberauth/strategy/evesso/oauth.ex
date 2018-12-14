defmodule Ueberauth.Strategy.EVESSO.OAuth do
  @moduledoc """
  Implements OAuth2 for EVE SSO v2 with JWT.

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
    site: "https://esi.evetech.net",
    authorize_url: "https://login.eveonline.com/v2/oauth/authorize",
    token_url: "https://login.eveonline.com/v2/oauth/token"
  ]

  @doc """
  Construct a client for requests to ESI

  Optionally include any OAuth2 options here to be merged with the defaults.

      Ueberauth.Strategy.EVESSO.Oauth.client(redirect_uri: "http://localhost:4000/auth/sso/callback")

  This will be set up automatically for you in `Ueberauth.Strategy.EVESSO`.
  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    config =
      :ueberauth
      |> Application.fetch_env!(Ueberauth.Strategy.EVESSO.OAuth)
      |> check_config_key_exists(:client_id)
      |> check_config_key_exists(:client_secret)

    client_opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    OAuth2.Client.new(client_opts)
  end

  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get(token, url, headers \\ [], opts \\ []) do
    [token: token]
    |> client()
    |> put_param("client_secret", client().client_secret)
    |> OAuth2.Client.get(url, headers, opts)
  end

  def verify(token) do
    token
    |> __MODULE__.get('/verify')
  end

  def get_token!(params \\[], options \\ []) do
    headers = Keyword.get(options, :headers, [])
    options = Keyword.get(options, :options, [])
    client_options = Keyword.get(options, :client_options, [])
    client = OAuth2.Client.get_token!(client(client_options), params, headers, options)
    client.token
  end

  # Strategy callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_param("client_secret", client().client_secret)
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end

  defp check_config_key_exists(config, key) when is_list(config) do
    unless Keyword.has_key?(config, key) do
      raise "#{inspect (key)} missing from config :ueberauth, Ueberauth.Strategy.EVESSO"
    end
    config
  end
  defp check_config_key_exists(_, _) do
    raise "Config :ueberauth, Ueberauth.Strategy.EVESSO is not a keyword list, as expected"
  end

end
