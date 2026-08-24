import type { ListingMeta } from "../api/types";

/**
 * THE TWO LIMITS THIS UI OWES THE USER, SAID QUIETLY.
 *
 * MEASURED (internal/webui/testdata/svar-contract/u0-measurements.json):
 *
 *   - The component does not virtualize. 100,000 entries produced 100,000 card
 *     elements, 1,000,067 DOM nodes and 703 MB of JS heap, and 17.7 s to open
 *     in cards mode / 33.3 s in table mode. So the API caps a listing -- the
 *     cap is the design, not a fallback -- and a capped listing that the UI
 *     does not admit to is a UI that says a directory has 5,000 entries when
 *     it has two million.
 *
 *   - Search is CLIENT-SIDE over loaded data only. Typing in the toolbar's
 *     search box fires no request at all (recording.json, step "search"); the
 *     store filters the subtree it happens to have. Combined with the cap, "no
 *     results" therefore means "not in what this tab has loaded", which is a
 *     different statement from "not in your volume" -- and the user cannot
 *     tell the two apart unless the UI says so.
 *
 * BOTH FACTS STAY. WHAT CHANGED IS THE VOLUME OF THEM, and it was a defect
 * rather than a preference. The first version printed, full width, above the
 * grid, before anyone had typed anything: "Search below is partial by design:
 * it matches only what this tab has already loaded and never asks the server.
 * For a whole-volume search, use pelfs mount and your own tools." That is an
 * implementation confession standing between a person and their files, and the
 * owner's verdict on it was "a BIZARRE thing to say".
 *
 * So each limit is now a chip in the file pane's accessory row -- beside the
 * pane whose search box it is about -- and the whole sentence is one click
 * away inside it. A <details>, deliberately: it needs no JavaScript and no
 * inline style, so it survives `script-src 'self'` and `style-src 'self'`; it
 * is keyboard-reachable and it exists on a touch screen, which a tooltip does
 * not. Nothing is hidden that a person cannot open, and nothing is shouted.
 */
export function SearchCaveat({ meta, search }: { meta: ListingMeta | null; search: string }) {
  const loaded = meta?.returned;
  return (
    <details
      className="pelfs-caveat"
      // One `name` for both caveats makes them an exclusive accordion in the
      // browser itself: opening one closes the other, so two popovers cannot
      // overlap. No JavaScript, and a browser that does not know the attribute
      // simply opens both.
      name="pelfs-caveat"
      data-testid="search-scope"
      data-searching={search ? "yes" : "no"}
    >
      <summary>
        {search ? (
          <>
            searching{" "}
            <strong data-testid="search-scope-count">{(loaded ?? 0).toLocaleString()}</strong> loaded
            rows
          </>
        ) : (
          <>search covers loaded rows</>
        )}
      </summary>
      <p className="pelfs-caveat__body">
        The search box filters the rows this tab has already loaded and asks the server nothing, so
        a file that exists but has not been listed here will not appear. For a whole-volume search,
        use <code>pelfs mount</code> or a WebDAV client.
      </p>
    </details>
  );
}

/**
 * The other half: this folder is bigger than what is on the screen.
 *
 * The server's own sentence for this is webapi.PartialSearchNotice, which says
 * the same two things in the same order -- how much is shown, and that the
 * search box is therefore searching only that much. It is served on
 * `GET /api/v1/info/{id}`; this page learns the numbers from the listing's
 * response headers instead (api/types.ts, ListingMeta) because the listing
 * body has to stay a bare JSON array. Same facts, one wording per surface.
 */
export function CapCaveat({ meta }: { meta: ListingMeta | null }) {
  if (!meta || meta.total === undefined || meta.total <= meta.returned) return null;
  return (
    <details
      className="pelfs-caveat pelfs-caveat--cap"
      name="pelfs-caveat"
      data-testid="listing-cap"
      data-listing-total={meta.total}
      data-listing-returned={meta.returned}
    >
      <summary>
        showing {meta.returned.toLocaleString()} of {meta.total.toLocaleString()}
      </summary>
      <p className="pelfs-caveat__body">
        This folder holds <strong>{meta.total.toLocaleString()}</strong> entries and this page is
        showing the first <strong>{meta.returned.toLocaleString()}</strong>
        {meta.cap ? ` (the server's cap is ${meta.cap.toLocaleString()})` : ""}. The browser cannot
        render the rest — the file list is not virtualized, and a directory this size costs hundreds
        of megabytes of memory and tens of seconds. Use <code>pelfs mount</code>, a WebDAV client,
        or a narrower path.
      </p>
    </details>
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
    <p className="pelfs-note pelfs-note--staged" data-testid="upload-notice" role="status">
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
    <div className="pelfs-note pelfs-note--bad" data-testid="pelfs-error" role="alert">
      <span>{text}</span>{" "}
      <button type="button" className="pelfs-button pelfs-button--quiet" onClick={onReload}>
        Reload the listing
      </button>
      <span className="pelfs-note__more">
        The listing above has been read back from the volume, so what you see is what the volume
        holds — the change you asked for is not in it. If this folder still looks wrong, the server
        did not answer the re-read either, and a reload is the way to be sure.
      </span>
    </div>
  );
}
