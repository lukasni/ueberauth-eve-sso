# Ueberauth Eve SSO

> EVE SSO v2 strategy for Überauth.

## Installation

1. Create an application at the [EVE Developer Page](https://developers.eveonline.com).

2. Add `:ueberauth_eve_sso` to your list of dependecies in `mix.exs`

  ```elixir
  def deps do
    [{:ueberauth_eve_sso, "~> 0.1.0"}]
  end
  ```

3. Add the strategy to your applications:

  ```elixir
  def application do
    [applications: [:ueberauth_eve_sso]]
  end
  ```

4. Add EVESSO to your Überauth configuration:

  ```elixir
  config :ueberauth, Ueberauth,
    providers: [
      evesso: {Ueberauth.Strategy.EVESSO, []}
    ]
  ```

5. Update your provider configuration using the `client_id` and `secret_key` generated in step 1 :

  ```elixir
  config :ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
    client_id: System.get_env("EVE_SSO_CLIENT_ID"),
    client_secret: System.get_env("EVE_SSO_CLIENT_SECRET")
  ```

## Calling

Depending on the configured url you can initiate the request through:

    /auth/sso

Or with options:

    /auth/sso?scope=esi-skills.read_skills.v1

You can configure the default scopes (configured in step 1) in your provider configuration. The scope parameter must be a list of scopes separated by a single space.

```elixir
config: ueberauth, Ueberauth,
  providers: [
    evesso: {Ueberauth.Strategy.EVESSO, [default_scope: "esi-skills.read_skills.v1 esi-skills.read_skillqueue.v1"]}
  ]
```


## License

Please see LICENSE for licensing details.


Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/ueberauth_eve_sso](https://hexdocs.pm/ueberauth_eve_sso).

