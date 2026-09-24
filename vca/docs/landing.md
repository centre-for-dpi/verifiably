# Landing

This page describes the `landing` service (ADR-033 and ADR-034). The
service README at [`services/landing/README.md`](../services/landing/README.md)
says how to run it. This page says how it works.

## The parts

| Package | Work |
|---|---|
| `config` | It reads the settings, the peer list of `VCA_PEERS`, and the image version. |
| `descriptor` | It builds the JSON document of `/.well-known/vca.json`. |
| `pages` | It renders the landing, the stacks fragment, the role picker, and the role intro pages. |
| `app` | It wires the prober, the theme file, the assets, and the pages. |

## What runs, and what shows

The landing knows every candidate pair of the deployment from
`VCA_PEERS`, which `vca setup` writes into `deploy/landing/.env`. It
never trusts that list as a fact. On every page view it asks the
`internal/topology` prober for a snapshot. The prober checks every pair in parallel.
One check stops after one second. The answer lives for fifteen seconds
(ADR-034 decision 2).

| State | What the prober found | What the page shows |
|---|---|---|
| Absent | The host of the home service does not resolve. | Nothing. The pair does not exist for the reader. |
| Starting | The host resolves, but `/readyz` does not answer `200` yet. | The role row of the stack carries the word `Starting`. No link. |
| Live | `/readyz` answers `200` and the adapter answered `GetCapabilities`. | The role row carries the word `Live`. The role counts as a way in. |

The stack cards come from the `GetCapabilities` answer of the live
adapters. Each card shows the display name of the stack and its pinned
version. It lists the components with their pinned versions. Each
component links to its repository and to its documentation. The service holds no vendor name: a
test fails when one appears in its source (ADR-001 decision 4). A stack
whose pairs all start, or whose only present pair is the admin, has no
adapter answer yet. Its card shows the short name of the stack until an
adapter answers.

The stacks block refreshes itself every thirty seconds through htmx. It
asks `/stacks` for the block alone and swaps it in place. A browser
without JavaScript keeps the block of the page load.

## The way in

The hero and the band at the foot of the page adapt to the live roles:

| Live roles | Primary action | Note under the hero |
|---|---|---|
| Two or more | `Start with VCA`, to the role picker at `/roles/`. | None. |
| One | `Continue as <role>`, to `/roles/<role>/`. | The role and the stacks it runs on. |
| None | No action. | No stack runs yet. |

## The role picker

`/roles/` shows one tile per live role among issuer, holder, and
verifier, with the stacks the role runs on. The admin comes as a band
at the foot of the page. A role with no live pair has no tile, and a
starting pair does not count (ADR-033 decision 5). With one live role
the picker answers `302` to the intro page of that role. With no live
role it says so and links back to the landing.

## The role intro pages

`/roles/<role>/` shows the step cards of one role, then the sign in
band. The lead names the count of steps, which follows the live
features (ADR-034 decision 5):

| Role | Steps | What changes |
|---|---|---|
| Issuer | Identify, define, issue, manage. | The issue step names OID4VCI when a live issuer stack speaks it. It names a QR on a PDF when one prints it. |
| Holder | Discover, claim, present, review. | The discover step appears when an issuer or a verifier is live, so there is something to discover. |
| Verifier | Discover, build a request, receive, check. | The build step names DCQL. It names DIF Presentation Exchange only when a live verifier stack lists that protocol. |
| Admin | Trust, registries, sign in, tenants, keys and audit. | The tenants step appears when a live stack separates tenants. |

The sign in band links to `<pair public URL>/auth/?return_to=<home>`
of the pair of the role. One live stack gives one button. Several give
one button per stack, named after the stack.

With one live stack the band names the provider and the realm. The
landing reads `GET <auth service>/auth/providers.json` of the pair on
the internal network, with a one second timeout. The admin pair has no
auth service, so the landing asks its home service. The first provider
of the listing gives the sentence, and the register flag adds the offer
to register. A listing the landing cannot read, or an empty one, keeps
the plain sentence. Several live stacks keep it too, because the realm
differs per stack.

A role with no live pair gets one sentence and a link back to the
picker. An unknown role answers `404`.

## The descriptor

`GET /.well-known/vca.json` returns one JSON document:

| Field | Content |
|---|---|
| `version` | The image version, from `VCA_VERSION`. |
| `public_url` | The address of the landing, when the deployment names one. |
| `taken` | The time of the probe behind the states, in UTC. |
| `stacks` | One entry per stack with a present pair: `id`, `name`, `version`, and `components` with `name`, `version`, `repository_url`, `docs_url`, and `license`. |
| `pairs` | One entry per present pair: `pair`, `role`, `stack`, `state` (`starting` or `live`), and `public_url`. |

An absent pair stays out of the document, as it stays off the page.

## Pages and routes

| Path | Page |
|---|---|
| `/` | The landing: header, hero, the three primer tiles, the stacks, the call to action, the footer. |
| `/stacks` | The stacks block alone, for the htmx refresh. |
| `/.well-known/vca.json` | The descriptor. |
| `/roles/` | The role picker. |
| `/roles/<role>/` | The intro page of one role. |

Every other path answers `404` with a page that links back to the
landing. Every page passes `a11ytest.AssertPage`, and the fragment
passes `a11ytest.AssertFragment`.

## Words and look

Every sentence comes from `internal/msg`. The look comes from the theme
file of the deployment, like every other page (ADR-032). The primer
tiles link out to the DPG Standard and to the W3C data model, so the
page stays short. The triangle of trust is an inline SVG figure with a
text equivalent.
