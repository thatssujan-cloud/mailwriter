/* ==========================================================================
   LetterDesk — js/backend-config.js
   Inline Tailwind CDN configuration: the "academic dashboard" palette.
   Status colors follow the spec: emerald #10B981 (confirmed), amber
   #F59E0B (estimated/pattern), rose #F43F5E (missing/unverified).
   Must load AFTER the Tailwind CDN script and BEFORE js/core.js.
   ========================================================================== */
// Inline Tailwind configuration — clean "academic dashboard" palette.
// Status colors follow the spec: emerald #10B981 (confirmed), amber
// #F59E0B (estimated/pattern), rose #F43F5E (missing/unverified).
tailwind.config = {
  theme: {
    extend: {
      colors: {
        slate: {
          DEFAULT: '#64748b',
          50:  '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
          950: '#020617'
        },
        ink: {
          DEFAULT: '#0f172a',
          50:  '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
          950: '#020617'
        },
        brand: {
          50:  '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
          800: '#3730a3',
          900: '#312e81'
        },
        forest: {
          50:  '#ecfdf5',
          100: '#d1fae5',
          200: '#a7f3d0',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10B981',
          600: '#059669',
          700: '#047857',
          800: '#065f46',
          900: '#064e3b'
        },
        clay: {
          50:  '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d',
          400: '#fbbf24',
          500: '#F59E0B',
          600: '#d97706',
          700: '#b45309',
          800: '#92400e',
          900: '#78350f'
        }
      },
      fontFamily: {
        display: ['"Plus Jakarta Sans"', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'Roboto', 'sans-serif'],
        sans: ['"Plus Jakarta Sans"', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'Arial', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace']
      },
      boxShadow: {
        card: '0 1px 2px rgba(15,23,42,0.06), 0 12px 32px -16px rgba(15,23,42,0.18)',
        lift: '0 12px 28px -12px rgba(79,70,229,0.45)'
      }
    }
  }
};
