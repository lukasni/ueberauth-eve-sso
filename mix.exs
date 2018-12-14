defmodule UeberauthEveSso.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :ueberauth_eve_sso,
      version: @version,
      name: "Ueberauth EVE SSO",
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:oauth2, "~> 0.9.4"},
      {:ueberauth, "~> 0.5.0"},
      {:jason, "~> 1.1"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},
    ]
  end
end
