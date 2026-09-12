/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#0a0e14",
          panel: "#0f1621",
          border: "#1e293b",
          critical: "#dc2626",
          high: "#ea580c",
          medium: "#ca8a04",
          low: "#2563eb",
          info: "#64748b",
          accent: "#22d3ee",
        },
      },
    },
  },
  plugins: [],
};
