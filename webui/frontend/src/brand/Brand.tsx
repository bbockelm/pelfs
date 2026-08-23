import { markUrl } from "./mark";

/**
 * The wordmark: the Pelican mark, unmodified, beside "pelfs" with the "fs"
 * in the brand blue. Option 1 of the two the design offers, chosen because
 * nothing is drawn on top of the mark, so nothing about the mark can be got
 * wrong.
 */
export function Brand({ subtitle }: { subtitle?: string }) {
  return (
    <div className="pelfs-brand" data-testid="pelfs-brand">
      <img
        className="pelfs-brand__mark"
        src={markUrl}
        // Deliberately not "Pelican Platform logo": this is pelfs, wearing a
        // borrowed mark with permission.
        alt="Pelican Platform mark"
        width={28}
        height={28}
      />
      <span className="pelfs-brand__word">
        pel<em>fs</em>
      </span>
      {subtitle ? <span className="pelfs-brand__sub">{subtitle}</span> : null}
    </div>
  );
}

/**
 * The line that keeps a borrowed mark from becoming a claim. It costs
 * nothing and prevents the one misunderstanding a borrowed mark can cause,
 * so it is part of the brand component rather than something a page can
 * forget to include.
 */
export function BrandFooter() {
  return (
    <footer className="pelfs-footer" data-testid="pelfs-disclaimer">
      <span>
        pelfs is an independent tool for Pelican federations — <strong>not</strong> an official
        Pelican Platform product. The Pelican mark is used with permission of the Pelican Project.
      </span>
      <a href="./third_party.txt" data-testid="pelfs-notices-link">
        third-party notices
      </a>
    </footer>
  );
}
