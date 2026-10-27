/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        // Customizing exact shades to match the high-end dev tool vibe
        zinc: {
          950: '#09090b',
          900: '#18181b',
          800: '#27272a',
          400: '#a1a1aa',
          50: '#fafafa',
        },
        indigo: {
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
        },
        // Custom color palette — cybersecurity-inspired dark theme
        brand: {
          50: '#eef9ff',
          100: '#d8f1ff',
          200: '#b9e8ff',
          300: '#89dbff',
          400: '#51c5ff',
          500: '#29a7ff',
          600: '#1189f5',
          700: '#0a70e1',
          800: '#0f5ab6',
          900: '#134d8f',
          950: '#0e3057',
        },
        surface: {
          50: '#f6f7f9',
          100: '#eceef2',
          200: '#d5d9e2',
          300: '#b1b8c9',
          400: '#8791ab',
          500: '#687491',
          600: '#535d78',
          700: '#444c62',
          800: '#3b4153',
          900: '#343947',
          950: '#0f1117',
        },
        accent: {
          green: '#10b981',
          red: '#ef4444',
          amber: '#f59e0b',
          purple: '#8b5cf6',
          cyan: '#06b6d4',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-out',
        'slide-up': 'slideUp 0.4s ease-out',
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'scan-line': 'scanLine 3s ease-in-out infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        pulseGlow: {
          '0%, 100%': { boxShadow: '0 0 5px rgba(41, 167, 255, 0.3)' },
          '50%': { boxShadow: '0 0 20px rgba(41, 167, 255, 0.6)' },
        },
        scanLine: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
}
