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
      description:
        "SPAKE2 password-authenticated key exchange over Ed25519 (BoringSSL-compatible)",
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
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.4/dist/katex.min.css" integrity="sha384-vKruj+a13U8yHIkAyGgK1J3ArTLzrFGBbBc0tDp4ad/EyewESeXE/Iv67Aj8gKZ0" crossorigin="anonymous">
  <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.4/dist/katex.min.js" integrity="sha384-PwRUT/YqbnEjkZO0zZxNqcxACrXe+j766U2amXcgMg5457rve2Y7I6ZJSm2A0mS4" crossorigin="anonymous"></script>
  <link href="https://cdn.jsdelivr.net/npm/katex-copytex@1.0.2/dist/katex-copytex.min.css" rel="stylesheet" type="text/css">
  <script defer src="https://cdn.jsdelivr.net/npm/katex-copytex@1.0.2/dist/katex-copytex.min.js" crossorigin="anonymous"></script>
  <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.4/dist/contrib/auto-render.min.js" integrity="sha384-+VBxd3r6XgURycqtZ117nYw44OOcIax56Z4dCRWbxyPt0Koah1uHoK0o4+/RRE05" crossorigin="anonymous"></script>
  <script>
    let initialized = false;

    window.addEventListener("exdoc:loaded", () => {
      if (!initialized) {
        mermaid.initialize({
          startOnLoad: false,
          theme: document.body.className.includes("dark") ? "dark" : "default"
        });

        renderMathInElement(document.body, {
          delimiters: [
            {left: '$$', right: '$$', display: true},
            {left: '$', right: '$', display: false},
          ]
        })

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
      extras: ["CHANGELOG.md"],
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
