import { defineConfig, loadEnv, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiBase = env.VITE_API_BASE || "http://localhost:8080";
  const apiOrigin = new URL(apiBase, "http://localhost").origin;
  const policies = contentSecurityPolicies(apiOrigin, mode === "development");
  const securityHeaders = {
    "Content-Security-Policy": policies.header,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer"
  };
  return {
    base: env.VITE_BASE_PATH || "/",
    plugins: [react(), contentSecurityPolicyMeta(policies.meta)],
    server: { headers: securityHeaders },
    preview: { headers: securityHeaders },
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

function contentSecurityPolicies(apiOrigin: string, development: boolean) {
  const scriptSource = development ? "script-src 'self' 'unsafe-inline'" : "script-src 'self'";
  const connectSource = development ? `connect-src 'self' ${apiOrigin} ws: wss:` : `connect-src 'self' ${apiOrigin}`;
  const directives = [
    "default-src 'self'",
    scriptSource,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: http: https:",
    "font-src 'self' data:",
    connectSource,
    "object-src 'none'",
    "base-uri 'self'"
  ];
  return {
    meta: directives.join("; "),
    header: [...directives, "frame-ancestors 'none'"].join("; ")
  };
}

function contentSecurityPolicyMeta(policy: string): Plugin {
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
