# The U0 probe

Two questions decided whether `@svar-ui/react-filemanager` could be used on a
pelfs volume at all, and neither was answerable from the documentation:

1. **Does it load a directory lazily**, or does it want the whole tree up
   front? A volume with 100k files must not become one request.
2. **Does it virtualize** a large directory's rendering? A 100,000-entry
   directory is ordinary here.

This directory answers them by driving the real component against a logging
stub in a real browser. It is work item **U0**, and M4 (the file manager) was
gated on its result.

## Running it

    pnpm probe          # answers both questions, sweeps directory sizes
    pnpm probe:record   # writes the wire-protocol fixture the Go tests replay

`pnpm probe` needs a browser: `pnpm exec playwright install chromium`
(~92 MiB download, ~11 s here). Nothing else in the repository needs any of
this — `go build`, `go vet` and `go test` need no Node at all.

## What it found

**1. It IS lazy — but only because the app makes it so.** Entries the server
marks `lazy: true` cause the store to emit `request-data` when that folder is
*navigated into*; the answer goes back as `provide-data`. The shipped
`RestDataProvider` registers **no handler for `request-data`**, so without the
wiring in `src/api/provider.ts` (`wireLazyLoading`) nothing loads at all. Two
further facts, both from the recording:

- expanding a folder in the **sidebar tree** does not load it; only
  navigation does (`set-path` is the only action that emits `request-data`);
- the store emits `request-data` **twice** for one navigation, which on a
  large directory is two full listings — hence the in-flight guard in
  `wireLazyLoading`;
- a folder already loaded is **never re-listed** except by the breadcrumb
  refresh button.

**2. It does NOT virtualize.** Every entry becomes DOM, in both card and table
mode, and scrolling to the bottom of a 100,000-entry directory changes
nothing because everything was already rendered. The measured sweep is in
`internal/webui/testdata/svar-contract/u0-measurements.json`:

| entries | cards mode | table mode | DOM nodes | JS heap |
|---|---|---|---|---|
| 1,000 | 0.1 s | 0.07 s | 10,067 | 13 MB |
| 5,000 | 0.3 s | 0.4 s | 50,067 | 40 MB |
| 20,000 | 1.4 s | 2.3 s | 200,067 | 148 MB |
| 50,000 | 6.3 s | 9.4 s | 500,067 | 364 MB |
| 100,000 | 18.1 s | 37.5 s | 1,000,067 | 703 MB |

So the JSON API's **response cap is the design, not a fallback**, and 5,000 is
a defensible number: it renders in under half a second. Search is
**client-side over what is already loaded**, so a capped listing is also a
partial search, and the UI has to say so.

## Three defects in the shipped provider

Two of them are in `recording.json`'s last step; the third is not on the wire
at all and was found by reading the method afterwards. This heading said
**two** for four commits, which is worth recording because the one it left out
is the only one that can cost a user their belief about the volume.

- `RestDataProvider.send()` overrides the base `Rest.send()` and spreads only
  its `customHeaders` argument — it never reads `this._customHeaders`. So
  `setHeaders()`, the documented way to attach a credential, is **silently
  dropped**. The session token is header-borne by design, so this is the
  credential, not a nicety.
- Every mutating request goes out as `Content-Type: text/plain;charset=UTF-8`,
  because the provider sets no content type and that is `fetch`'s default for
  a string body. `text/plain` is one of the three types an HTML form can
  send, so the threat model's "mutating route with `text/plain` → 415" row
  would reject every write the file manager makes.
- **It swallows every failure.** The shipped `send` attaches its `.catch`
  AFTER its own `!res.ok` throw, so the throw it just made is caught by it: a
  401, a 415, a 500 or a torn connection all resolve to `undefined` and the
  promise never rejects. A wire trace cannot show this — the request and the
  response are both correct — which is why it took reading the method.

`PelfsDataProvider` in `../src/api/provider.ts` fixes all three: `send()` is a
full override doing its own fetch, so the happy path is identical and a failure
is a rejected promise. The recording shows the difference on the wire for the
first two.

There is a fourth thing, and it is NOT a defect in the provider — it is what
the third one hides. The store applies every mutation optimistically, and a
rejected promise rolls none of it back, so `send()` rejecting is necessary and
not sufficient: without more, a refused rename gave an error banner beside a
row that kept the new name. `PelfsDataProvider.getHandlers` closes it by
re-listing from the server; see that method, and
`../tests/filemanager.spec.ts`'s refused-rename test, which is the assertion
that fails if any of this regresses.

## And it phones home unless told not to

The default theme renders `<link rel=stylesheet
href=https://cdn.svar.dev/fonts/wxi/wx-icons.css>` plus a preconnect, and the
default icon callback builds `https://cdn.svar.dev/icons/...` per file
extension. `<Willow fonts={false}>` and `icons="simple"` remove both, and the
probe then measures **zero** requests off loopback. `vite.config.ts`'s
`offlineAssets` plugin is what keeps it that way.
