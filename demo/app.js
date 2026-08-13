const byId = (id) => document.getElementById(id);
const toast = byId("toast");
let downloadUrl;

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab, .panel").forEach((element) => element.classList.remove("active"));
    button.classList.add("active");
    byId(button.dataset.panel).classList.add("active");
  });
});

document.querySelectorAll('input[name="payload-kind"]').forEach((radio) => {
  radio.addEventListener("change", () => {
    const file = radio.value === "file" && radio.checked;
    byId("secret-field").hidden = file;
    byId("file-field").hidden = !file;
  });
});

byId("sample-cover").addEventListener("click", () => {
  const lines = [
    "I am sending the notes from today so we have them in one place.",
    "There is no rush on any of this; look when you have a quiet minute.",
    "The weather changed again, and the streets were much calmer this afternoon.",
    "I will check the remaining details tomorrow and let you know what I find.",
    "For now, everything here can wait until the rest of the week.",
  ];
  byId("cover").value = Array.from({ length: 45 }, (_, index) => lines[index % lines.length]).join(" ");
  notify("Loaded a synthetic test cover.");
});

byId("estimate").addEventListener("click", async () => {
  await withButton(byId("estimate"), async () => {
    const result = await run("capacity", [byId("hide-carrier").value, "password", 0]);
    byId("capacity-result").textContent = `${result.max_payload_bytes} byte hard payload limit`;
  });
});

byId("hide-submit").addEventListener("click", async () => {
  await withButton(byId("hide-submit"), async () => {
    const cover = byId("cover").value;
    const password = byId("hide-password").value;
    const carrier = byId("hide-carrier").value;
    const createdAt = Math.floor(Date.now() / 1000);
    const kind = document.querySelector('input[name="payload-kind"]:checked').value;
    let result;
    if (kind === "file") {
      const file = byId("secret-file").files[0];
      if (!file) throw new Error("Choose a file first.");
      result = await run("hide-file", [cover, file.name, new Uint8Array(await file.arrayBuffer()), password, carrier, createdAt]);
    } else {
      result = await run("hide-text", [cover, byId("secret").value, password, carrier, createdAt]);
    }
    byId("hide-password").value = "";
    byId("stego").value = result.text;
    byId("hide-report").textContent = JSON.stringify(result.report, null, 2);
    byId("hide-output").hidden = false;
    byId("received").value = result.text;
    byId("inspect-text").value = result.text;
  });
});

byId("copy-stego").addEventListener("click", () => copy(byId("stego").value));

byId("reveal-submit").addEventListener("click", async () => {
  await withButton(byId("reveal-submit"), async () => {
    const result = await run("reveal", [byId("received").value, byId("reveal-password").value]);
    byId("reveal-password").value = "";
    byId("reveal-output").hidden = false;
    byId("download-file").hidden = true;
    if (result.kind === "text") {
      byId("opened").textContent = result.text;
      return;
    }
    const bytes = Uint8Array.from(atob(result.bytes_base64), (character) => character.charCodeAt(0));
    if (downloadUrl) URL.revokeObjectURL(downloadUrl);
    downloadUrl = URL.createObjectURL(new Blob([bytes]));
    const button = byId("download-file");
    button.hidden = false;
    button.dataset.name = result.file_name;
    byId("opened").textContent = `${result.file_name}\n${bytes.length} bytes`;
  });
});

byId("download-file").addEventListener("click", () => {
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = byId("download-file").dataset.name || "sayeh-payload.bin";
  link.click();
});

byId("scan-submit").addEventListener("click", async () => {
  await withButton(byId("scan-submit"), async () => {
    const result = await run("scan", [byId("inspect-text").value]);
    showJson("inspect-output", result);
  });
});

byId("strip-submit").addEventListener("click", async () => {
  await withButton(byId("strip-submit"), async () => {
    const result = await run("strip", [byId("inspect-text").value]);
    byId("inspect-text").value = result;
    showJson("inspect-output", { stripped: true, visible_text: result });
  });
});

byId("probe-generate").addEventListener("click", async () => {
  await withButton(byId("probe-generate"), async () => {
    byId("probe-text").value = await run("probe-generate", []);
  });
});
byId("copy-probe").addEventListener("click", () => copy(byId("probe-text").value));
byId("probe-analyse").addEventListener("click", async () => {
  await withButton(byId("probe-analyse"), async () => {
    showJson("probe-output", await run("probe-analyse", [byId("probe-text").value]));
  });
});

async function run(operation, args) {
  const worker = new Worker("worker.js", { type: "module" });
  return new Promise((resolve, reject) => {
    worker.onmessage = ({ data }) => {
      worker.terminate();
      data.ok ? resolve(data.result) : reject(new Error(data.error));
    };
    worker.onerror = (event) => {
      worker.terminate();
      reject(new Error(event.message || "The WebAssembly worker failed."));
    };
    worker.postMessage({ operation, args });
  });
}

async function withButton(button, task) {
  button.disabled = true;
  try {
    await task();
  } catch (error) {
    notify(error.message || String(error), true);
  } finally {
    button.disabled = false;
  }
}

function showJson(id, value) {
  const output = byId(id);
  output.hidden = false;
  output.textContent = JSON.stringify(value, null, 2);
}

async function copy(value) {
  try {
    await navigator.clipboard.writeText(value);
    notify("Copied. Some clipboard paths may strip invisible characters; verify before relying on it.");
  } catch {
    notify("Clipboard access was denied. Select and copy the text manually.", true);
  }
}

function notify(message, error = false) {
  toast.textContent = message;
  toast.style.background = error ? "#7f312d" : "";
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 4200);
}
