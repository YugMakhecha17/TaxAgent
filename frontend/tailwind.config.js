/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'dark-grey': '#2D2D2D',
        'light-grey': '#3A3A3A',
        'accent-grey': '#4A4A4A',
        'text-grey': '#E0E0E0',
        'border-grey': '#555555',
        // Add border-grey as a color that can be used with border-border-grey utility
      },
    },
  },
  plugins: [],
}

