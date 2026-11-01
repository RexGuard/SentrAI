// Files the operator attaches to a question: logs and other text files are read here and sent as text; screenshots
// are sent as base64 pictures. Limits match the core (mvp/core/app/chat.py check_attachments).
export type Attachment = { name: string; kind: 'text' | 'image'; size: number; text?: string; media_type?: string; data?: string }

export const MAX_FILES = 3
const IMAGE = ['image/png', 'image/jpeg', 'image/webp', 'image/gif']
const MAX_TEXT_BYTES = 1_000_000
const MAX_IMAGE_BYTES = 4_400_000
export const ACCEPT = '.log,.txt,.json,.csv,.conf,.cfg,.ini,.xml,.yaml,.yml,.md,text/*,' + IMAGE.join(',')

/** Reads one file, or says in plain words why it cannot be attached. */
export async function read(file: File): Promise<Attachment> {
  if (IMAGE.includes(file.type)) {
    if (file.size > MAX_IMAGE_BYTES) throw new Error(`${file.name} is too big (pictures up to 4 MB).`)
    const url: string = await new Promise((ok, fail) => {
      const r = new FileReader(); r.onload = () => ok(String(r.result)); r.onerror = () => fail(r.error); r.readAsDataURL(file)
    })
    return { name: file.name || 'screenshot.png', kind: 'image', size: file.size, media_type: file.type, data: url.slice(url.indexOf(',') + 1) }
  }
  if (file.type.startsWith('image/')) throw new Error(`${file.name}: pictures must be PNG, JPEG, WebP or GIF.`)
  if (file.size > MAX_TEXT_BYTES) throw new Error(`${file.name} is too big (text files up to 1 MB; send the part around the problem).`)
  const text = await file.text()
  if (text.includes('\u0000')) throw new Error(`${file.name} does not look like a text file.`)
  if (!text.trim()) throw new Error(`${file.name} is empty.`)
  return { name: file.name, kind: 'text', size: file.size, text }
}

export const sizeLabel = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${Math.round(n / 1024)} KB` : `${(n / 1048576).toFixed(1)} MB`)
