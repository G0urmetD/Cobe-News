import { useTheme } from "@/lib/theme"
import { Toaster as Sonner, type ToasterProps } from "sonner"
// the toasts' CSS as a file of this origin – the build keeps sonner from injecting it as a <style> (src/lib/no-inline-styles.ts)
import "sonner/dist/styles.css"
import { CircleCheckIcon, InfoIcon, TriangleAlertIcon, OctagonXIcon, Loader2Icon } from "lucide-react"

const Toaster = ({ ...props }: ToasterProps) => {
  const { theme = "system" } = useTheme()

  return (
    <Sonner
      theme={theme as ToasterProps["theme"]}
      // pointer-events-auto: a modal drawer or dialog sets pointer-events: none on <body> – the toasts' buttons
      // ("Rückgängig", "Zur Liste") must stay clickable while one is open
      className="toaster group pointer-events-auto"
      icons={{
        success: <CircleCheckIcon className="size-4" />,
        info: <InfoIcon className="size-4" />,
        warning: <TriangleAlertIcon className="size-4" />,
        error: <OctagonXIcon className="size-4" />,
        loading: <Loader2Icon className="size-4 animate-spin" />,
      }}
      style={
        {
          "--normal-bg": "var(--popover)",
          "--normal-text": "var(--popover-foreground)",
          "--normal-border": "var(--border)",
          "--border-radius": "var(--radius)",
        } as React.CSSProperties
      }
      toastOptions={{
        classNames: {
          toast: "cn-toast",
        },
      }}
      {...props}
    />
  )
}

export { Toaster }
