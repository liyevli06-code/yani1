/** @type {import('tailwindcss').Config} */
function withOpacity(variable) {
  return ({ opacityValue }) =>
    opacityValue === undefined ? `rgb(var(${variable}))` : `rgb(var(${variable}) / ${opacityValue})`;
}

module.exports = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Bricolage Grotesque", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        paper: withOpacity("--c-paper"),
        surface: withOpacity("--c-surface"),
        ink: {
          DEFAULT: withOpacity("--c-ink"),
          soft: withOpacity("--c-ink-soft"),
          faint: withOpacity("--c-ink-faint"),
        },
        line: withOpacity("--c-line"),
        signal: { DEFAULT: withOpacity("--c-signal"), dark: withOpacity("--c-signal-dark") },
        ok: withOpacity("--c-ok"),
        redir: withOpacity("--c-redir"),
        warn: withOpacity("--c-warn"),
        bad: withOpacity("--c-bad"),
      },
    },
  },
  plugins: [],
};
