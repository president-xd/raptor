/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        raptor: {
          bg: '#07080e',
          surface: '#0c0e18',
          card: '#121624',
          border: '#1f2638',
          accent: '#3b82f6',
          accent2: '#60a5fa',
          danger: '#ef4444',
          warning: '#f59e0b',
          success: '#22c55e',
          info: '#3b82f6',
          text: '#dde2f0',
          muted: '#7c8aa2',
        },
      },
      fontFamily: {
        sans: ['IBM Plex Sans', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['IBM Plex Mono', 'JetBrains Mono', 'Consolas', 'monospace'],
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
