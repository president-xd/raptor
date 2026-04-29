/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        raptor: {
          bg: '#f8f8f1',
          surface: '#f8f8f1',
          card: '#e8e8e3',
          border: '#cdcdcb',
          accent: '#10100e',
          accent2: '#000000',
          danger: '#b42318',
          warning: '#8a5b00',
          success: '#146c43',
          info: '#10100e',
          text: '#10100e',
          muted: '#686864',
        },
      },
      fontFamily: {
        sans: ['IBM Plex Mono', 'GeistMono', 'ui-monospace', 'SFMono-Regular', 'Roboto Mono', 'Menlo', 'monospace'],
        mono: ['IBM Plex Mono', 'GeistMono', 'ui-monospace', 'SFMono-Regular', 'Roboto Mono', 'Menlo', 'monospace'],
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
