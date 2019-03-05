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

  @doc """
  Provides the authorize url for the request phase of Ueberauth.
  This will usually not have to be called directly.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  @doc """
  Perform an authorized GET request to `url` using the `token`.
  Url can be either relative to the `site` or absolute.
  """
  def get(token, url, headers \\ [], opts \\ []) do
    [token: token]
    |> client()
    |> put_param("client_secret", client().client_secret)
    |> OAuth2.Client.get(url, headers, opts)
  end

  @doc """
  Verify a token with ESI and prime the Auth cache. Will return token owner details
  """
  def verify(token) do
    result = __MODULE__.get(token, "/verify")

    case result do
      {:ok, %OAuth2.Response{body: body, headers: _headers, status_code: 200}} -> {:ok, body}
      _ -> {:error, {:verification_error, result}}
    end
  end

  @doc """
  Retrieve character details and portrait urls for the owner of a token
  """
  def subject(token, id) do
    with {:ok, %OAuth2.Response{body: char_body, headers: _headers, status_code: 200}} <-
           __MODULE__.get(token, "/v4/characters/#{id}"),
         {:ok, %OAuth2.Response{body: pict_body, headers: _headers, status_code: 200}} <-
           __MODULE__.get(token, "/v2/characters/#{id}/portrait/") do
      {:ok, Map.merge(char_body, %{"portrait" => pict_body, "character_id" => id})}
    else
      err -> {:error, err}
    end
  end

  def get_token!(params \\ [], options \\ []) do
    headers = Keyword.get(options, :headers, [])
    options = Keyword.get(options, :options, [])
    client_options = Keyword.get(options, :client_options, [])
    client = OAuth2.Client.get_token!(client(client_options), params, headers, options)
    client.token
  end

  @doc """
  Get a new access token using a `refresh_token`. Will raise an error if the refresh fails
  """
  def refresh_token!(refresh_token) do
    client = client(strategy: OAuth2.Strategy.Refresh)
    |> put_param("refresh_token", refresh_token)
    |> put_header("Accept", "application/json")
    |> put_header("Host", "login.eveonline.com")
    |> OAuth2.Client.get_token!
  end

  @doc """
  Get a new access token using a `refresh_token`
  """
  def refresh_token(refresh_token) do
    client = client(strategy: OAuth2.Strategy.Refresh)
    |> put_param("refresh_token", refresh_token)
    |> put_header("Accept", "application/json")
    |> put_header("Host", "login.eveonline.com")
    |> OAuth2.Client.get_token
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
      raise "#{inspect(key)} missing from config :ueberauth, Ueberauth.Strategy.EVESSO"
    end

    config
  end

  defp check_config_key_exists(_, _) do
    raise "Config :ueberauth, Ueberauth.Strategy.EVESSO is not a keyword list, as expected"
  end
end
