defmodule Spake2.MixProject do
  use Mix.Project

  @source_url "https://github.com/tv-labs/spake2"
  @version "0.1.0"

  def project do
    [
      app: :spake2,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      name: "Spake2",
      description: "SPAKE2 password-authenticated key exchange over Ed25519 (BoringSSL-compatible)",
      source_url: @source_url,
      homepage_url: @source_url,
      package: package(),
      docs: docs(),
      deps: deps()
    ]
  end

  defp package do
    [
      maintainers: ["David Bernheisel"],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url
      },
      files: ~w[lib mix.exs LICENSE CHANGELOG.md]
    ]
  end

  @mermaid_js """
  <script defer src="https://cdn.jsdelivr.net/npm/mermaid@11.12.2/dist/mermaid.min.js"></script>
  <script>
    let initialized = false;

    window.addEventListener("exdoc:loaded", () => {
      if (!initialized) {
        mermaid.initialize({
          startOnLoad: false,
          theme: document.body.className.includes("dark") ? "dark" : "default"
        });
        initialized = true;
      }

      let id = 0;
      for (const codeEl of document.querySelectorAll("pre code.mermaid")) {
        const preEl = codeEl.parentElement;
        const graphDefinition = codeEl.textContent;
        const graphEl = document.createElement("div");
        const graphId = "mermaid-graph-" + id++;
        mermaid.render(graphId, graphDefinition).then(({svg, bindFunctions}) => {
          graphEl.innerHTML = svg;
          bindFunctions?.(graphEl);
          preEl.insertAdjacentElement("afterend", graphEl);
          preEl.remove();
        });
      }
    });
  </script>
  """


  defp docs do
    [
      main: "Spake2",
      extras: [
        "CHANGELOG.md": [title: "Changelog"]
      ],
      source_url: "https://github.com/tv-labs/spake2",
      before_closing_body_tag: %{html: @mermaid_js},
      source_ref: "v#{@version}"
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:stream_data, "~> 1.0", only: :test},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false, warn_if_outdated: true},
      {:tidewave, "~> 0.5", only: :dev, warn_if_outdated: true},
      {:exsync, "~> 0.4", only: :dev},
      {:bandit, "~> 1.0", only: :dev}
    ]
  end
end
