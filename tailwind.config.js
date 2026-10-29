/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        lavender: {
          DEFAULT: "#F8F7FC",
          50: "#FAF9FD",
          100: "#F8F7FC",
          200: "#EDE9FE",
          300: "#DDD6FE",
        },
        purple: {
          accent: "#8B5CF6",
        },
        brand: {
          purple: "#8B5CF6",
          hover: "#7C3AED",
          active: "#6D28D9",
          light: "#A78BFA",
          subtle: "#F5F3FF",
        }
      },
      fontFamily: {
        sans: ['Segoe UI', 'Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['Cascadia Code', 'JetBrains Mono', 'Consolas', 'monospace'],
      }
    },
  },
  plugins: [],
}
