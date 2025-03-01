import daisyui from "daisyui";

/** @type {import('tailwindcss').Config} */
export default {
  // content: ["./src/**/*.{html,js}"],
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {},
  },
  plugins: [daisyui],
  daisyui: {
    themes: [
      "light",
      "dark",
      "cupcake",
      "bumblebee",
      "retro",
      "black",
      "sunset",
    ],
  },
};
