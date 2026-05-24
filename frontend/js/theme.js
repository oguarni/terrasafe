/*
 * Shared Tailwind (Play CDN) configuration for every TerraVault page.
 *
 * Colors resolve to `rgb(var(--c-token) / <alpha-value>)`, so each utility
 * reads its channels from the CSS variables in css/theme.css and respects
 * opacity modifiers. Swapping the `.dark` class on <html> reassigns those
 * variables, which is what makes the light/dark toggle actually repaint.
 *
 * Loaded as a synchronous <script> immediately after the Tailwind CDN so the
 * config is set before Tailwind builds styles on DOMContentLoaded.
 */
const themeColor = (token) => `rgb(var(--c-${token}) / <alpha-value>)`;

tailwind.config = {
    darkMode: "class",
    theme: {
        extend: {
            colors: {
                "on-surface": themeColor("on-surface"),
                "on-primary-container": themeColor("on-primary-container"),
                "on-tertiary-fixed-variant": themeColor("on-tertiary-fixed-variant"),
                "on-secondary": themeColor("on-secondary"),
                "background": themeColor("background"),
                "outline-variant": themeColor("outline-variant"),
                "error": themeColor("error"),
                "secondary-container": themeColor("secondary-container"),
                "surface-variant": themeColor("surface-variant"),
                "inverse-surface": themeColor("inverse-surface"),
                "primary-container": themeColor("primary-container"),
                "tertiary-fixed-dim": themeColor("tertiary-fixed-dim"),
                "on-error-container": themeColor("on-error-container"),
                "surface-container-low": themeColor("surface-container-low"),
                "primary-fixed": themeColor("primary-fixed"),
                "on-tertiary-container": themeColor("on-tertiary-container"),
                "surface-bright": themeColor("surface-bright"),
                "on-secondary-container": themeColor("on-secondary-container"),
                "surface-container": themeColor("surface-container"),
                "surface-container-highest": themeColor("surface-container-highest"),
                "secondary-fixed-dim": themeColor("secondary-fixed-dim"),
                "tertiary-container": themeColor("tertiary-container"),
                "inverse-on-surface": themeColor("inverse-on-surface"),
                "surface-container-lowest": themeColor("surface-container-lowest"),
                "on-error": themeColor("on-error"),
                "on-primary-fixed": themeColor("on-primary-fixed"),
                "tertiary-fixed": themeColor("tertiary-fixed"),
                "outline": themeColor("outline"),
                "on-secondary-fixed-variant": themeColor("on-secondary-fixed-variant"),
                "on-background": themeColor("on-background"),
                "surface-container-high": themeColor("surface-container-high"),
                "on-surface-variant": themeColor("on-surface-variant"),
                "surface-dim": themeColor("surface-dim"),
                "inverse-primary": themeColor("inverse-primary"),
                "error-container": themeColor("error-container"),
                "tertiary": themeColor("tertiary"),
                "primary-fixed-dim": themeColor("primary-fixed-dim"),
                "on-primary": themeColor("on-primary"),
                "surface-tint": themeColor("surface-tint"),
                "secondary-fixed": themeColor("secondary-fixed"),
                "on-primary-fixed-variant": themeColor("on-primary-fixed-variant"),
                "secondary": themeColor("secondary"),
                "on-secondary-fixed": themeColor("on-secondary-fixed"),
                "primary": themeColor("primary"),
                "on-tertiary": themeColor("on-tertiary"),
                "on-tertiary-fixed": themeColor("on-tertiary-fixed"),
                "surface": themeColor("surface")
            },
            fontFamily: {
                "headline": ["Inter", "sans-serif"],
                "body": ["Inter", "sans-serif"],
                "label": ["Inter", "sans-serif"],
                "mono": ["monospace"]
            },
            borderRadius: { "DEFAULT": "0.25rem", "lg": "0.5rem", "xl": "0.75rem", "full": "9999px" }
        }
    }
};
