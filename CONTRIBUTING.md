# Contributing

## Rule changes

Every detection change must include:

- at least one positive fixture that demonstrates the intended behavior;
- at least one relevant negative fixture or a written reason one is not applicable;
- an updated methodology note when assumptions or limitations change; and
- a passing regression suite.

Run:

    python -m unittest discover -s tests -v

Use inert synthetic fixtures or redistributable public samples with documented provenance. Never commit secrets, proprietary data, customer information, or live weaponized content.
