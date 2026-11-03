import * as React from "react"

const MOBILE_BREAKPOINT = 768

// the window's width as an outside store: read during render (no first render with the wrong layout), and the query's
// change events re-render
function subscribe(onChange: () => void) {
  const mql = window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`)
  mql.addEventListener("change", onChange)
  return () => mql.removeEventListener("change", onChange)
}

const isMobileNow = () => window.innerWidth < MOBILE_BREAKPOINT
const onServer = () => false

export function useIsMobile() {
  return React.useSyncExternalStore(subscribe, isMobileNow, onServer)
}
