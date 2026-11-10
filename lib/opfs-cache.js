// Model cache in the Origin Private File System. The default Cache API can
// refuse single files around 1 GB (Qwen3-VL's decoder weights are 995 MB);
// OPFS streams them to disk instead. Implements Transformers.js'
// custom-cache interface: match(url) and put(url, response).

const DIR = "models";

async function dir() {
  const root = await navigator.storage.getDirectory();
  return root.getDirectoryHandle(DIR, { create: true });
}

async function keyFor(url) {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(url));
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function writeStream(handle, stream) {
  if (handle.createWritable) {
    const w = await handle.createWritable();
    await stream.pipeTo(w);
    return;
  }
  // Safari: synchronous access handles (only available inside a worker).
  const access = await handle.createSyncAccessHandle();
  try {
    access.truncate(0);
    let at = 0;
    const reader = stream.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      at += access.write(value, { at });
    }
    access.flush();
  } finally {
    access.close();
  }
}

export class OPFSCache {
  static async available() {
    try {
      await dir();
      return true;
    } catch {
      return false;
    }
  }

  async match(url) {
    try {
      const d = await dir();
      const file = await (await d.getFileHandle(await keyFor(url))).getFile();
      if (!file.size) return undefined;
      return new Response(file, { headers: { "content-length": String(file.size) } });
    } catch {
      return undefined;
    }
  }

  async put(url, response) {
    const d = await dir();
    const key = await keyFor(url);
    const part = `${key}.part`;
    try {
      const handle = await d.getFileHandle(part, { create: true });
      await writeStream(handle, response.body);
      // Only a complete download gets the real name, so an interrupted write
      // is never mistaken for a cached file.
      if (handle.move) await handle.move(key);
      else {
        const file = await handle.getFile();
        await writeStream(await d.getFileHandle(key, { create: true }), file.stream());
        await d.removeEntry(part);
      }
    } catch (err) {
      console.warn("Could not store a model file on this device:", err);
      try { await d.removeEntry(part); } catch {}
    }
  }

  async delete(url) {
    try {
      await (await dir()).removeEntry(await keyFor(url));
      return true;
    } catch {
      return false;
    }
  }
}

// Total bytes stored and whether every listed URL is present.
export async function cacheStatus(urls = []) {
  let bytes = 0;
  const names = new Set();
  try {
    const d = await dir();
    for await (const [name, handle] of d.entries()) {
      if (name.endsWith(".part")) continue;
      names.add(name);
      bytes += (await handle.getFile()).size;
    }
  } catch {}
  const keys = await Promise.all(urls.map(keyFor));
  return { bytes, complete: keys.every((k) => names.has(k)) };
}

export async function clearCache() {
  const root = await navigator.storage.getDirectory();
  await root.removeEntry(DIR, { recursive: true });
}
