// The i18n module touches document/localStorage when the language changes – a minimal stand-in for node. Defined
// outright: reading node's own experimental localStorage first would print a warning on every run.
const store = { getItem: () => null, setItem: () => undefined, removeItem: () => undefined }
Object.defineProperty(globalThis, "localStorage", { value: store, configurable: true, writable: true })
Object.defineProperty(globalThis, "document", { value: { documentElement: {}, cookie: "" }, configurable: true, writable: true })
