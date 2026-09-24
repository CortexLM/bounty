<div align="center">

# Bounty

![Bounty](assets/banner.jpg)

</div>

Bounty is the `bounty` challenge of the [Cortex](https://github.com/CortexLM/cortex)
Bittensor subnet. Miners pair a hotkey with a dedicated Cortex Chat account and file
reproducible bug reports about the Cortex product and backend. Each `valid` report
published by the CortexLM/backend public feed is worth one point to its author.

This repository builds the challenge container. The Cortex master runs it on a
private network, keeps it up to date from `ghcr.io/cortexlm/bounty`, proxies its
public routes at `https://<gateway>/challenge/bounty/` and reads its weights once
per completed epoch.

| Guide | For |
| --- | --- |
| [docs/miner.md](docs/miner.md) | pairing a hotkey and filing reports |
| [docs/operator.md](docs/operator.md) | running, configuring, adjudicating and migrating |
| [docs/scoring.md](docs/scoring.md) | how valid reports become emission |
| [docs/api.md](docs/api.md) | every route, its authentication, limits and errors |
| [docs/architecture.md](docs/architecture.md) | the container, feed, epochs and updates |

```bash
uv sync --group dev
uv run pytest
```

Licensed under [Apache-2.0](LICENSE).
