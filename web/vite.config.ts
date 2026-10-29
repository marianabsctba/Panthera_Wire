import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// No GitHub Pages o site fica em /Panthera_Wire/.
export default defineConfig({
  base: "/Panthera_Wire/",
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false },
});
