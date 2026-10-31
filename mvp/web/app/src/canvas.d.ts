declare module '*/flow_canvas.mjs' {
  export default function mount(component: {
    parentElement: ShadowRoot | HTMLElement
    data: unknown
    setTriggerValue: (name: string, value: unknown) => void
  }): void
}
declare module '*/routing_editor.mjs' {
  export default function mount(component: {
    parentElement: ShadowRoot | HTMLElement
    data: unknown
    setTriggerValue: (name: string, value: unknown) => void
  }): void
}
declare module '*/limits_map.mjs' {
  export default function mount(component: {
    parentElement: ShadowRoot | HTMLElement
    data: unknown
    setTriggerValue: (name: string, value: unknown) => void
  }): void
}
declare module '*.css?raw' { const css: string; export default css }
