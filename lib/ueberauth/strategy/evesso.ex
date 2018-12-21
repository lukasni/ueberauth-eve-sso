defmodule Ueberauth.Strategy.EVESSO do
  use Ueberauth.Strategy,
    uid_field: "CharacterID",
    default_scope: "",
    oauth2_module: Ueberauth.Strategy.EVESSO.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Construct redirect to EVE login servers with required scopes and state parameter.

  TODO: Examples
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    send_redirect_uri = Keyword.get(options(conn), :send_redirect_uri, true)

    opts =
      if send_redirect_uri do
        [redirect_uri: callback_url(conn), scope: scopes]
      else
        [scope: scopes]
      end

    opts =
      if conn.params["state"], do: Keyword.put(opts, :state, conn.params["state"]), else: opts

    module = option(conn, :oauth2_module)
    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  @doc """
  Accept the callback from EVE login servers, use OAuth2 provider
  to fetch access token using the auth code, then verify the token
  and construct Auth struct.

  TODO: Examples
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    module = option(conn, :oauth2_module)
    token = apply(module, :get_token!, [[code: code]])

    if token.access_token == nil do
      conn
      |> set_errors!([error(token.other_params["error"], token.other_params["error_description"])])
    else
      conn
      |> fetch_user(token)
    end
  end

  @doc """
  Catch-all callback clause to handle incorrect requests to the callback.
  """
  def handle_callback!(conn) do
    conn
    |> set_errors!([error("missing_code", "No code received")])
  end

  @doc """
  Remove the token and user from the connection after
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:sso_token, nil)
    |> put_private(:sso_user, nil)
  end

  @doc """
  Fetch the uid fioeld from the ESI Verify response. Defaults to the option uid_field
  which in turn defaults to CharacterID
  """
  def uid(conn) do
    conn |> option(:uid_field) |> to_string() |> fetch_uid(conn)
  end

  def credentials(conn) do
    token = conn.private.sso_token
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, " ")

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      scopes: scopes
    }
  end

  def info(conn) do
    %{verify: user, char: character} = conn.private.sso_user

    %Info{
      name: user["CharacterName"],
      description: character["description"],
      urls: %{
        portrait: character["portrait"],
        avatar_url: character["portrait"]["px128x128"]
      }
    }
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.sso_token,
        user: conn.private.sso_user
      }
    }
  end

  # Private helpers

  defp fetch_uid(:transfer_aware, conn) do
    character_id = conn.private.sso_user.verify["CharacterID"]
    owner_hash = conn.private.sso_user.verify["CharacterOwnerHash"]

    "#{character_id} #{owner_hash}"
  end

  defp fetch_uid(field, conn) do
    conn.private.sso_user.verify[field] || conn.private.sso_user.char[field]
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :sso_token, token)

    with {:ok, auth_response} <- Ueberauth.Strategy.EVESSO.OAuth.verify(token),
         {:ok, char_response} <-
           Ueberauth.Strategy.EVESSO.OAuth.subject(token, auth_response["CharacterID"]) do
      put_private(conn, :sso_user, %{verify: auth_response, char: char_response})
    else
      err -> err
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
