// The Pelican Platform mark, and the one place its URL is written.
//
// It is a PNG because that is the only form that exists: a search of the
// whole pelican tree outside node_modules finds no Pelican SVG at all, and
// the design's instruction is to use the PNG rather than trace or redraw the
// bird (a redraw of someone's mark is worse than their own file).
//
// TO SWAP IN A REAL SVG LATER: drop it next to the PNG in public/brand/ and
// change the one line below. Nothing else imports the asset path, and the
// CSS sizes by height, so a vector needs no other change.
export const markUrl = "./brand/PelicanPlatformLogo_Icon.png";

// Used with the permission of the Pelican Project's PI. pelfs is not an
// official Pelican Platform product; see public/brand/NOTICE.txt and the
// repository's NOTICE file.
export const markNotice =
  "The Pelican Platform mark is used with permission of the Pelican Project. " +
  "pelfs is an independent tool for Pelican federations, not an official " +
  "Pelican Platform product.";
