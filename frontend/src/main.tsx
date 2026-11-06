import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { RouterProvider, createBrowserRouter } from "react-router"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ThemeProvider } from "@/lib/theme"
import { i18nReady } from "@/i18n"
import "./index.css"
import App from "./App"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Toaster } from "@/components/ui/sonner"
import { ApiError } from "@/lib/api"
import { AuthProvider } from "@/lib/auth"
import { ConfirmHost } from "@/components/cobe/confirm"
import { ReauthHost } from "@/components/cobe/reauth"
import { OfflineNotice } from "@/components/cobe/offline-notice"
import { PageErrorBoundary, retryable } from "@/components/cobe/query-state"

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // a network hiccup or a server error is tried twice more; a refusal (4xx) is an answer
      retry: (count, err) => count < 2 && retryable(err) && !(err instanceof ApiError && err.status < 500),
      refetchOnWindowFocus: false,
    },
  },
})

function Root() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <TooltipProvider delayDuration={300}>
          <App />
          <ConfirmHost />
          <ReauthHost />
          <OfflineNotice />
          <Toaster position="bottom-center" richColors closeButton />
        </TooltipProvider>
      </AuthProvider>
    </QueryClientProvider>
  )
}

const router = createBrowserRouter([{ path: "*", element: <Root /> }])

void i18nReady
  .catch(() => undefined)
  .then(() =>
    createRoot(document.getElementById("root")!).render(
      <StrictMode>
        <ThemeProvider>
          <PageErrorBoundary resetKey="" full>
            <RouterProvider router={router} />
          </PageErrorBoundary>
        </ThemeProvider>
      </StrictMode>,
    ),
  )
