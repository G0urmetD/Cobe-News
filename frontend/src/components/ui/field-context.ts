import { createContext, useContext } from "react"

/** The id a <Field/> gives its control: the label is then linked (click and screen readers) without wiring each one. */
export const FieldIdContext = createContext<string | undefined>(undefined)
export const useFieldId = () => useContext(FieldIdContext)

/**
 * What names a <Field/>'s control that is no input (a button opening a list: MultiSelect) – the id for its
 * aria-labelledby: the label, or only its text when the label has an explanation (<Explained/>: text and an info
 * button), so the control is named "Themen", not "Themen" and the explanation.
 */
export const FieldLabelIdContext = createContext<string | undefined>(undefined)
export const useFieldLabelId = () => useContext(FieldLabelIdContext)
/** Inside a <Field/>'s label only: the id for the label's text, and `use` – <Explained/> says it carries it. */
export const FieldLabelTextContext = createContext<{ id: string; use: (on: boolean) => void } | undefined>(undefined)
export const useFieldLabelText = () => useContext(FieldLabelTextContext)
