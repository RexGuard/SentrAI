// Voice input with the browser's own speech recognition (Chrome, Edge, Safari). Some browsers send the audio to
// their maker's service to turn it into text, so the page says so next to the microphone.
type Rec = {
  lang: string; interimResults: boolean; continuous: boolean
  onresult: ((e: { resultIndex: number; results: ArrayLike<ArrayLike<{ transcript: string }> & { isFinal: boolean }> }) => void) | null
  onend: (() => void) | null; onerror: ((e: { error: string }) => void) | null
  start: () => void; stop: () => void
}
type RecCtor = new () => Rec

const ctor = (): RecCtor | undefined => {
  const w = window as unknown as { SpeechRecognition?: RecCtor; webkitSpeechRecognition?: RecCtor }
  return w.SpeechRecognition ?? w.webkitSpeechRecognition
}
export const canListen = () => typeof window !== 'undefined' && !!ctor()

/** Starts listening. `onText(final, interim)` gets the words so far; returns a function that stops. */
export function listen(onText: (final: string, interim: string) => void, onEnd: (error?: string) => void): () => void {
  const C = ctor()
  if (!C) { onEnd('Voice input is not available in this browser.'); return () => {} }
  const r = new C()
  r.lang = navigator.language || 'en-US'; r.interimResults = true; r.continuous = true
  let final = ''
  r.onresult = (e) => {
    let interim = ''
    for (let i = e.resultIndex; i < e.results.length; i++) {
      const res = e.results[i]
      if (res.isFinal) final += res[0].transcript; else interim += res[0].transcript
    }
    onText(final, interim)
  }
  r.onerror = (e) => onEnd(e.error === 'not-allowed' ? 'The browser was not allowed to use the microphone.' : e.error === 'no-speech' ? undefined : `Voice input stopped: ${e.error}`)
  r.onend = () => onEnd()
  r.start()
  return () => r.stop()
}
