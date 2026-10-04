// Sealed demo script entry: script:translate:run.mjs
//
// `seal pack` maps demo/translate/scripts/run.mjs to the entry id `script:translate:run.mjs`.
// At run time the dsh sealed-script tool delivers THIS SOURCE on the child's stdin
// (`node --input-type=module - <source>`) and appends the model-supplied `input` argument after the
// `-` separator, so `process.argv[2]` is the text to translate. The source itself is never written
// to disk or placed on argv by the plugin; it is decrypted in memory and zeroized after the run.
//
// The glossary is a deliberately tiny stand-in for a real translation backend so the demo stays
// offline and deterministic. It prints the translated text to stdout.

const GLOSSARY = {
  '你好': 'hello',
  '谢谢': 'thanks',
  '世界': 'world',
  '再见': 'goodbye',
}

const input = (process.argv[2] ?? '').trim()
const translated = input.replace(/你好|谢谢|世界|再见/g, (word) => GLOSSARY[word] ?? word)
process.stdout.write(translated + '\n')