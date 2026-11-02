import { useEffect, useState } from "react"

/** The value once it has not changed for `ms` – what typing settles on (a check or a search asks the server for that). */
export function useSettled<T>(value: T, ms = 400): T {
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setSettled(value), ms)
    return () => clearTimeout(id)
  }, [value, ms])
  return settled
}
