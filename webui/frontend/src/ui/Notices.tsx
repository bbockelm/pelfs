import type { ListingMeta } from "../api/types";

/**
 * The two sentences this UI owes the user about its own limits, and they are
 * sentences rather than icons because both limits are silent.
 *
 * MEASURED (internal/webui/testdata/svar-contract/u0-measurements.json):
 *
 *   - The component does not virtualize. 100,000 entries produced 100,000
 *     card elements, 1,000,067 DOM nodes and 703 MB of JS heap, and 17.7 s to
 *     open in cards mode / 33.3 s in table mode. So the API caps a listing --
 *     the cap is the design, not a fallback -- and a capped listing that the
 *     UI does not admit to is a UI that says a directory has 5,000 entries
 *     when it has two million.
 *
 *   - Search is CLIENT-SIDE over loaded data only. Typing in the toolbar's
 *     search box fires no request at all (recording.json, step "search"); the
 *     store filters the subtree it happens to have. Combined with the cap,
 *     "no results" therefore means "not in what this tab has loaded", which
 *     is a different statement from "not in your volume" -- and the user
 *     cannot tell the two apart unless the UI says so.
 *
 * Both sentences sit immediately above the component's own toolbar, whose
 * search box is at its top left, so the search caveat is beside the box it is
 * about. Not a tooltip: a tooltip is invisible to a person who does not think
 * to hover, and on a touch screen it does not exist.
 */
export function ListingNotices({
  meta,
  search,
}: {
  meta: ListingMeta | null;
  search: string;
}) {
  const truncated = !!meta && meta.total !== undefined && meta.total > meta.returned;

  return (
    <div className="pelfs-notices" data-testid="pelfs-notices">
      <p className="pelfs-notice" data-testid="search-scope" data-searching={search ? "yes" : "no"}>
        {search ? (
          <>
            <strong>This search is partial.</strong> It matches only the{" "}
            <strong data-testid="search-scope-count">{meta?.returned ?? 0}</strong> entries this tab
            has already loaded, in this folder and the folders you have opened. It asks the server
            nothing. A file that exists but has not been listed here will not appear.
          </>
        ) : (
          <>
            Search below is <strong>partial by design</strong>: it matches only what this tab has
            already loaded and never asks the server. For a whole-volume search, use{" "}
            <code>pelfs mount</code> and your own tools.
          </>
        )}
      </p>

      {truncated ? (
        <p
          className="pelfs-notice pelfs-notice--cap"
          data-testid="listing-cap"
          data-listing-total={meta?.total}
          data-listing-returned={meta?.returned}
        >
          <strong>This folder is shown in part.</strong> It holds{" "}
          <strong>{meta?.total?.toLocaleString()}</strong> entries; this page is showing the first{" "}
          <strong>{meta?.returned.toLocaleString()}</strong>
          {meta?.cap ? ` (the server's cap is ${meta.cap.toLocaleString()})` : ""}. The browser
          cannot render the rest — the file list is not virtualized, and{" "}
          {meta?.total && meta.total >= 100000 ? "100,000" : "a directory this size"} entries costs
          hundreds of megabytes of memory and tens of seconds. Use <code>pelfs mount</code>, a
          WebDAV client, or a narrower path for a directory this large.
        </p>
      ) : null}
    </div>
  );
}

/**
 * What "uploaded" means, said at the moment it is most likely to be
 * misunderstood.
 *
 * A browser upload finishes and the file appears in the grid. At that instant
 * the bytes are in the local overlay -- durable against `kill -9`, invisible
 * to the federation -- and the user's next action is to close the laptop.
 * docs/design-guiclients.md measured the trap: 200 documents at ~2 MB fires
 * neither the 1 GiB nor the 200,000-inode pressure trigger, so nothing is
 * published for up to five minutes, and a browser tab has no unmount.
 */
export function UploadNotice({ text }: { text: string }) {
  if (!text) return null;
  return (
    <p className="pelfs-notice pelfs-notice--staged" data-testid="upload-notice" role="status">
      {text}
    </p>
  );
}

/**
 * A failed operation, said out loud -- beside a listing that has already been
 * put back.
 *
 * The store applies every change optimistically, so a refused rename used to
 * leave the new name on the screen with this banner underneath it: two
 * answers, and the screen is the one a user believes. The provider now
 * re-lists the directories a failed mutation touched and hands the server's
 * answer back to the store (api/provider.ts, `getHandlers`), so by the time
 * this appears the row is the volume's row again and the banner says only what
 * did not happen.
 *
 * The reload button stays, for the case the repair cannot cover: a server that
 * is not answering at all fails the re-listing too, and then a full reload is
 * the only thing left. It is offered rather than performed, because a page
 * that reloads itself on an error is a page that can lose an unsent rename in
 * another folder.
 */
export function ErrorBanner({ text, onReload }: { text: string; onReload: () => void }) {
  if (!text) return null;
  return (
    <div className="pelfs-banner pelfs-banner--bad" data-testid="pelfs-error" role="alert">
      <span>{text}</span>{" "}
      <button type="button" className="pelfs-button pelfs-button--quiet" onClick={onReload}>
        Reload the listing
      </button>
      <div className="pelfs-muted">
        The listing above has been read back from the volume, so what you see is what the volume
        holds — the change you asked for is not in it. If this folder still looks wrong, the
        server did not answer the re-read either, and a reload is the way to be sure.
      </div>
    </div>
  );
}
