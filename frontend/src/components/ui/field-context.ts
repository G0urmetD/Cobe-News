import { createContext, useContext } from "react"

/** The id a <Field/> gives its control: the label is then linked (click and screen readers) without wiring each one. */
export const FieldIdContext = createContext<string | undefined>(undefined)
export const useFieldId = () => useContext(FieldIdContext)
