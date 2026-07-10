import { defineConfig, loadEnv, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiBase = env.VITE_API_BASE || "http://localhost:8080";
  const apiOrigin = new URL(apiBase, "http://localhost").origin;
  return {
    base: env.VITE_BASE_PATH || "/",
    plugins: [react(), contentSecurityPolicy(apiOrigin, mode === "development")],
    build: {
      target: "es2022",
      rollupOptions: {
        output: {
          manualChunks: {
            react: ["react", "react-dom"],
            antd: ["antd", "@ant-design/icons"],
            query: ["@tanstack/react-query"]
          }
        }
      }
    }
  };
});

function contentSecurityPolicy(apiOrigin: string, development: boolean): Plugin {
  const scriptSource = development ? "script-src 'self' 'unsafe-inline'" : "script-src 'self'";
  const connectSource = development ? `connect-src 'self' ${apiOrigin} ws: wss:` : `connect-src 'self' ${apiOrigin}`;
  const policy = [
    "default-src 'self'",
    scriptSource,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: http: https:",
    "font-src 'self' data:",
    connectSource,
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'"
  ].join("; ");
  return {
    name: "admin-content-security-policy",
    transformIndexHtml: {
      order: "pre",
      handler: () => [{
        tag: "meta",
        attrs: { "http-equiv": "Content-Security-Policy", content: policy },
        injectTo: "head-prepend"
      }]
    }
  };
}
