defmodule Ueberauth.Strategy.EVESSO do

  use Ueberauth.Strategy,
    uid_field: :id,
    default_scope: "",
    oauth2_module: Ueberauth.Strategy.EVESSO.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

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

  def handle_callback!(conn) do
    conn
    |> set_errors!([error("missing_code", "No code received")])
  end

  def handle_cleanup!(conn) do
    conn
    |> put_private(:sso_token, nil)
    |> put_private(:sso_user, nil)
  end


  # Private helpers

  defp fetch_user(conn, token) do
    conn = put_private(conn, :sso_token, token)

    with {:ok, response} <- Ueberauth.Strategy.EVESSO.OAuth.verify(token),
         %OAuth2.Response{body: body, headers: _headers, status_code: 200} <- response,
         {:ok, user} <- Jason.decode(body)
    do
      put_private(conn, :sso_user, user)
    else
      err -> err
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
