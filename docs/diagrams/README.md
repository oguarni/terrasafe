# Runtime architecture diagram

`terravault-runtime-architecture-v7.tex` is the LuaLaTeX/TikZ source for the
two-panel runtime plate: deployment topology in panel A, the shared scan
pipeline in panel B. `build.sh` compiles it in both languages and publishes six
files into the portfolio repository.

Every figure on the plate is checked against this tree rather than written from
memory — the 11 rules, the 8-column feature vector, the score weights, the
request cap and scan timeout, the rate limits, the `:ro` mounts, the
private-range `/metrics` handler, and the scrape interval all have a source of
truth in the code. If you change one of those, the plate is stale until it is
rebuilt.

## Prerequisites

The build refuses to start unless all six binaries are on `PATH`. On
Debian, Ubuntu, and Mint:

```bash
sudo apt install \
    texlive-base texlive-binaries \
    texlive-latex-base texlive-latex-recommended texlive-latex-extra \
    texlive-pictures texlive-fonts-extra \
    dvisvgm poppler-utils imagemagick inkscape
```

| Binary | Package | Used for |
|---|---|---|
| `lualatex` | `texlive-latex-base`, `texlive-binaries` | compiles the plate |
| `pdftoppm` | `poppler-utils` | rasterises the PDF at 600 dpi |
| `convert`, `identify` | `imagemagick` | downsamples to PNG and WebP |
| `dvisvgm` | `dvisvgm` | vector cut for the lightbox |
| `inkscape` | `inkscape` | rasterises the SVG for the integrity check only |

The LaTeX side needs `standalone` (`texlive-latex-extra`), `etoolbox` and
`xcolor` (`texlive-latex-recommended`), TikZ (`texlive-pictures`), Fira Sans and
Fira Mono (`texlive-fonts-extra`), and the Computer Modern math faces
(`texlive-base`). `texlive-full` also works and skips the bookkeeping.

If LuaTeX cannot write its font cache — a read-only `HOME`, a container, a
sandbox — point it somewhere writable rather than running as root:

```bash
export TEXMFVAR="$PWD/.texmf-var" TEXMFCACHE="$PWD/.texmf-var"
```

## Building

```bash
./build.sh
```

That compiles `pt` and `en`, then writes into `../../../oguarni.github.io/assets/img/`:
a full-resolution PNG, an SVG, and a 1400px WebP card per language. The publish
step runs only after **both** languages succeed, so the portfolio can never be
left with one language updated and the other stale.

Three environment variables override the defaults:

| Variable | Default | Meaning |
|---|---|---|
| `DIAGRAM_SOURCE_BASENAME` | `terravault-runtime-architecture-v7` | which `.tex` to compile |
| `DIAGRAM_OUTPUT_BASENAME` | `terravault-runtime-architecture` | published filename stem |
| `DIAGRAM_DERIVATIVE_WIDTH` | `1400` | card width in pixels |

The card was 900px until the legend was measured at roughly a 7px em — a
thumbnail rather than something a reader can use. 1400 costs about 79KB instead
of 43KB. Changing the width changes the published filename, so grep the
portfolio repo for the old one before you do.

## The two gates

Both exist because this plate has failed in exactly these ways before, and both
fail the build rather than warn.

**Any LaTeX warning is fatal.** `Overfull`, `Underfull`, and `Missing character`
all abort. An overfull box is a clipped label, and a clipped label ships as a
diagram that quietly says something other than what it means. Because every text
width here is measured against the longer of the two languages, Portuguese is
usually what trips it first.

**The SVG is compared against the raster.** Inkscape's poppler-based PDF import
mangles this plate — it drops the second character of `fi`/`fl` ligatures, eats
spaces around `m`, and renders the floor delimiters of the hybrid score as a
literal `b` and `c` — while exiting 0. Silent corruption is the failure mode, so
the SVG is rasterised and compared against the PNG built from the same PDF.
Both sides are blurred first to discard the antialiasing disagreement between
the two rasterisers, which would otherwise dominate the score. A correct
`dvisvgm` cut lands near 0.007; the mangled Inkscape one scored 0.021 against a
0.015 threshold. This is why the SVG comes from `dvisvgm` and Inkscape appears
only as the checker.

## Editing

Coordinates are hand-measured and every text width is sized from the longest
line in **both** languages, so changing a label can push a node into its
neighbour without any warning firing. Rebuild and look at the plate.

Horizontal space is the scarce axis: the page is rasterised at a fixed width, so
a wider canvas shrinks every glyph while extra height costs nothing. Spread rows
vertically before packing columns.

Only the published revision is tracked. Earlier drafts exist in some working
trees but are deliberately not committed, so `DIAGRAM_SOURCE_BASENAME` will only
resolve to something that is actually in the repository.
