package reporthtml

// DateTimeFormatOptionsJS is the Intl.DateTimeFormat options object literal
// the generated reports use to render timestamps in the viewer's locale and
// time zone. It names the components explicitly: ECMA-402 rejects dateStyle or
// timeStyle combined with timeZoneName with a TypeError, which left every
// report timestamp on its UTC fallback text.
const DateTimeFormatOptionsJS = `{year:'numeric',month:'short',day:'numeric',hour:'numeric',minute:'2-digit',timeZoneName:'short'}`
