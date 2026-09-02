import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { AlertHubApp } from "./AlertHubApp";
import "./globals.css";
import { getAppName } from "./product";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      gcTime: 5 * 60 * 1000,
      refetchOnWindowFocus: false,
      retry: false,
      staleTime: 0,
    },
  },
});

function setMeta(selector: string, value: string) {
  document.querySelector<HTMLMetaElement>(selector)?.setAttribute("content", value);
}

const appName = getAppName();
const pageTitle = `${appName} — Distributed operations console`;
document.title = pageTitle;
setMeta('meta[name="application-name"]', appName);
setMeta('meta[name="apple-mobile-web-app-title"]', appName);
setMeta('meta[property="og:site_name"]', appName);
setMeta('meta[property="og:title"]', pageTitle);
setMeta('meta[name="twitter:title"]', pageTitle);

const root = document.getElementById("root");
if (!root) throw new Error("Alert Hub root element is missing");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AlertHubApp appName={appName} />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
