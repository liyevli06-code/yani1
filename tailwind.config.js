/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./app/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Bricolage Grotesque", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        paper: "#EEF1F3",
        ink: { DEFAULT: "#0B1F33", soft: "#475A6C", faint: "#6B7C8C" },
        line: "#D3DAE0",
        signal: { DEFAULT: "#C84A04", dark: "#A63C02" },
        ok: "#16794C",
        redir: "#2257C5",
        warn: "#98600A",
        bad: "#B3261E",
      },
    },
  },
  plugins: [],
};
