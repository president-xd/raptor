/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        raptor: {
          paper: '#f8f8f1',
          'paper-2': '#f3f2eb',
          linen: '#ecebe3',
          'linen-2': '#e2e1d8',
          fog: '#d4d3c9',
          rule: '#cdcdcb',
          graphite: '#686864',
          slate: '#4a4a44',
          ink: '#10100e',
          oxblood: '#b42318',
          'oxblood-tint': '#f7e5e2',
          brass: '#8a5b00',
          'brass-tint': '#f5ecd6',
          forest: '#146c43',
          'forest-tint': '#dcebe1',
          indigo: '#2f3f78',
          'indigo-tint': '#e3e6f0',
        },
      },
      fontFamily: {
        mono: ['IBM Plex Mono', 'ui-monospace', 'SFMono-Regular', 'Roboto Mono', 'Menlo', 'monospace'],
        sans: ['IBM Plex Sans', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Helvetica', 'Arial', 'sans-serif'],
        serif: ['IBM Plex Serif', 'Source Serif Pro', 'Georgia', 'Times New Roman', 'serif'],
      },
      animation: {
        'slide-up': 'slideUp 0.22s ease-out',
        'fade-in': 'fadeIn 0.2s ease-out',
      },
      keyframes: {
        slideUp: {
          '0%': { transform: 'translateY(8px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
};
