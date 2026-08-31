#!/usr/bin/env bash

set -euo pipefail

export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH=1704067200
umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORTFOLIO_ASSETS="${SCRIPT_DIR}/../../../oguarni.github.io/assets/img"
SOURCE_BASENAME="${DIAGRAM_SOURCE_BASENAME:-terravault-runtime-architecture-v7}"
OUTPUT_BASENAME="${DIAGRAM_OUTPUT_BASENAME:-terravault-runtime-architecture}"
DERIVATIVE_WIDTH="${DIAGRAM_DERIVATIVE_WIDTH:-1400}"
TEMP_DIR="$(mktemp -d "/tmp/${OUTPUT_BASENAME}.XXXXXX")"

cleanup() {
    for lang in pt en; do
        rm -f \
            "${SCRIPT_DIR}/${OUTPUT_BASENAME}-${lang}.aux" \
            "${SCRIPT_DIR}/${OUTPUT_BASENAME}-${lang}.log" \
            "${SCRIPT_DIR}/${OUTPUT_BASENAME}-${lang}.out" \
            "${SCRIPT_DIR}/${OUTPUT_BASENAME}-${lang}.pdf"
    done
    case "${TEMP_DIR}" in
        "/tmp/${OUTPUT_BASENAME}."*) rm -rf "${TEMP_DIR}" ;;
        *) printf 'Refusing to clean unexpected temporary directory: %s\n' "${TEMP_DIR}" >&2 ;;
    esac
}
trap cleanup EXIT

for command_name in lualatex pdftoppm convert identify dvisvgm inkscape; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        printf 'Required command not found: %s\n' "${command_name}" >&2
        exit 1
    fi
done

if [[ ! -d "${PORTFOLIO_ASSETS}" ]]; then
    printf 'Portfolio image directory not found: %s\n' "${PORTFOLIO_ASSETS}" >&2
    exit 1
fi

if [[ ! -f "${SCRIPT_DIR}/${SOURCE_BASENAME}.tex" ]]; then
    printf 'Diagram source not found: %s\n' "${SCRIPT_DIR}/${SOURCE_BASENAME}.tex" >&2
    exit 1
fi

if [[ ! "${DERIVATIVE_WIDTH}" =~ ^[1-9][0-9]*$ ]]; then
    printf 'DIAGRAM_DERIVATIVE_WIDTH must be a positive integer: %s\n' "${DERIVATIVE_WIDTH}" >&2
    exit 1
fi

cd "${SCRIPT_DIR}"

for lang in pt en; do
    job="${OUTPUT_BASENAME}-${lang}"
    pdf="${SCRIPT_DIR}/${job}.pdf"
    log="${SCRIPT_DIR}/${job}.log"
    raster_600="${TEMP_DIR}/${job}-600.png"
    output_png="${TEMP_DIR}/${job}.png"
    output_webp="${TEMP_DIR}/${job}-${DERIVATIVE_WIDTH}.webp"
    output_svg="${TEMP_DIR}/${job}.svg"
    warnings="${TEMP_DIR}/${job}-warnings.txt"

    printf 'Compiling %s...\n' "${job}"
    lualatex --interaction=nonstopmode --halt-on-error -jobname="${job}" \
        "\def\diaglang{${lang}}\input{${SOURCE_BASENAME}.tex}"

    if grep -E '(LaTeX|Package [^ ]+) Warning:|Overfull|Underfull|Missing character' \
        "${log}" > "${warnings}"; then
        printf 'LaTeX emitted warnings for %s:\n' "${job}" >&2
        sed 's/^/  /' "${warnings}" >&2
        exit 1
    fi

    pdftoppm -png -r 600 -singlefile "${pdf}" "${TEMP_DIR}/${job}-600"
    convert "${raster_600}" -resize 3121x -filter Lanczos -strip "${output_png}"
    convert "${output_png}" -resize "${DERIVATIVE_WIDTH}x" -strip -quality 84 "${output_webp}"
    # dvisvgm, not inkscape. Inkscape's poppler-based PDF import silently
    # mangles this plate: it drops the second character of the fi/fl ligatures
    # ("verifica" -> "verifca", "fluxo" -> "fuxo", "confiança" -> "confança"),
    # splits or eats spaces around "m" ("Prometheus" -> "Prom etheus",
    # "Parser HCL" -> "ParserHCL"), and renders the floor delimiters of the
    # hybrid score as a literal "b" and "c". It exits 0 while doing it, so the
    # damage only shows when the SVG is opened. dvisvgm is built for TeX output
    # and reproduces the page exactly; --no-fonts emits glyphs as paths, which
    # is what --export-text-to-path was asking for.
    dvisvgm --pdf --page=1 --no-fonts --output="${output_svg}" "${pdf}"

    # Silent corruption is this step's failure mode — inkscape exited 0 while
    # producing an unreadable plate — so the SVG is compared against the raster
    # built from the same PDF instead of being trusted. Both sides are blurred
    # first: that discards the antialiasing disagreement between the two
    # rasterisers, which otherwise dominates the score, while missing or
    # substituted glyphs stay visible. Measured on this plate: a correct
    # dvisvgm SVG scores 0.008, the mangled inkscape one 0.021.
    svg_check="${TEMP_DIR}/${job}-svgcheck.png"
    png_check="${TEMP_DIR}/${job}-pngcheck.png"
    inkscape "${output_svg}" --export-type=png --export-width=1200 \
        --export-filename="${svg_check}" >/dev/null 2>&1
    convert "${output_png}" -resize 1200x -background white -alpha remove \
        -alpha off -blur 0x1.2 "${png_check}"
    rmse="$(convert "${svg_check}" -background white -alpha remove -alpha off \
        -blur 0x1.2 "${png_check}" -metric RMSE -compare \
        -format '%[distortion]' info: 2>/dev/null)"
    if awk -v value="${rmse}" 'BEGIN { exit !(value > 0.015) }'; then
        printf 'SVG does not match the rendered page for %s (RMSE %s)\n' \
            "${job}" "${rmse}" >&2
        exit 1
    fi
    printf '  %s SVG matches the rendered page (RMSE %s)\n' "${job}" "${rmse}"

done

# Publish only after both language builds succeed, so the portfolio can never
# be left with one language updated and the other stale.
for lang in pt en; do
    job="${OUTPUT_BASENAME}-${lang}"
    cp "${TEMP_DIR}/${job}.png" "${PORTFOLIO_ASSETS}/${job}.png"
    cp "${TEMP_DIR}/${job}-${DERIVATIVE_WIDTH}.webp" \
        "${PORTFOLIO_ASSETS}/${job}-${DERIVATIVE_WIDTH}.webp"
    cp "${TEMP_DIR}/${job}.svg" "${PORTFOLIO_ASSETS}/${job}.svg"
done

printf 'Built portfolio assets:\n'
for output in \
    "${PORTFOLIO_ASSETS}/${OUTPUT_BASENAME}-pt.png" \
    "${PORTFOLIO_ASSETS}/${OUTPUT_BASENAME}-en.png" \
    "${PORTFOLIO_ASSETS}/${OUTPUT_BASENAME}-pt-${DERIVATIVE_WIDTH}.webp" \
    "${PORTFOLIO_ASSETS}/${OUTPUT_BASENAME}-en-${DERIVATIVE_WIDTH}.webp" \
    "${PORTFOLIO_ASSETS}/${OUTPUT_BASENAME}-pt.svg" \
    "${PORTFOLIO_ASSETS}/${OUTPUT_BASENAME}-en.svg"; do
    identify -format '  %f %wx%h\n' "${output}"
done
