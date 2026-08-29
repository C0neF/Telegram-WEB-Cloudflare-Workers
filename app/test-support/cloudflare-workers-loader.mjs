const shimUrl = new URL('./cloudflare-workers-shim.mjs', import.meta.url).href;

export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'cloudflare:workers') {
    return { shortCircuit: true, url: shimUrl };
  }
  return nextResolve(specifier, context);
}
