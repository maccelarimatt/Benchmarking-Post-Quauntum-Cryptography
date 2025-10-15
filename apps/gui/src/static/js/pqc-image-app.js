(function () {
  "use strict";

  const PANEL_KEYS = ["original", "ciphertext", "wrongKey", "randomPad", "recovered"];

  const state = {
    fileBytes: null,
    originalImage: null,
    width: 0,
    height: 0,
    encryptResult: null,
    verifyState: "pending",
    recoveredImage: null,
    entropy: {
      original: null,
      ciphertext: null,
      wrongKey: null,
      randomPad: null,
      recovered: null,
    },
    includeAlpha: false,
    heatmapVisible: {
      original: false,
      ciphertext: false,
      wrongKey: false,
      randomPad: false,
      recovered: false,
    },
    heatmapOnly: {
      original: false,
      ciphertext: false,
      wrongKey: false,
      randomPad: false,
      recovered: false,
    },
    histogramPanel: "original",
    originalBase64: null,
    wrongKeyBase64: null,
    recoveredBase64: null,
    randomPadBase64: null,
  };

  const dom = {
    panels: {},
    heatmapButtons: {},
    heatmapOnlyButtons: {},
  };

  const DEFAULT_IMAGE_PATH = "/static/test%20images/Capture1.JPG";
  const DEFAULT_IMAGE_NAME = "Capture1.JPG";

  function qs(id) {
    const el = document.getElementById(id);
    if (!el) {
      throw new Error(`Missing element: ${id}`);
    }
    return el;
  }

  function initDom() {
    dom.fileInput = qs("image-input");
    dom.kemSelect = qs("kem-select");
    dom.sigSelect = qs("sig-select");
    dom.demoSeed = qs("demo-seed");
    dom.includeAlpha = qs("include-alpha");
    dom.btnEncrypt = qs("btn-encrypt");
    dom.btnDecrypt = qs("btn-decrypt");
    dom.btnWrong = qs("btn-wrong");
    dom.status = qs("status");
    dom.error = qs("error");

    dom.canvasOriginal = qs("canvas-original");
    dom.canvasCipher = qs("canvas-cipher");
    dom.canvasWrong = qs("canvas-wrong");
    dom.canvasRandom = qs("canvas-random");
    dom.canvasRecovered = qs("canvas-recovered");

    dom.heatmapOriginal = qs("heatmap-original");
    dom.heatmapCiphertext = qs("heatmap-ciphertext");
    dom.heatmapWrongKey = qs("heatmap-wrongKey");
    dom.heatmapRandomPad = qs("heatmap-randomPad");

    dom.entropyOriginal = qs("entropy-original");
    dom.entropyCiphertext = qs("entropy-ciphertext");
    dom.entropyWrongKey = qs("entropy-wrongKey");
    dom.entropyRandomPad = qs("entropy-randomPad");
    dom.entropyRecovered = qs("entropy-recovered");

    dom.modal = qs("recovered-modal");
    dom.modalClose = qs("modal-close");

    dom.histModal = qs("histogram-modal");
    dom.histClose = qs("histogram-close");
    dom.histCanvasR = qs("histogram-r");
    dom.histCanvasG = qs("histogram-g");
    dom.histCanvasB = qs("histogram-b");

    dom.badge = qs("badge-verify");
    dom.infoKem = qs("info-kem");
    dom.infoSig = qs("info-sig");
    dom.infoNonce = qs("info-nonce");
    dom.infoCtLen = qs("info-ctlen");
    dom.infoKemTime = qs("info-kemtime");
    dom.infoSymTime = qs("info-symtime");
    dom.infoDemoSeed = qs("info-demoseed");

    dom.panels = {
      original: { canvas: dom.canvasOriginal, heatmap: dom.heatmapOriginal, metrics: dom.entropyOriginal },
      ciphertext: { canvas: dom.canvasCipher, heatmap: dom.heatmapCiphertext, metrics: dom.entropyCiphertext },
      wrongKey: { canvas: dom.canvasWrong, heatmap: dom.heatmapWrongKey, metrics: dom.entropyWrongKey },
      randomPad: { canvas: dom.canvasRandom, heatmap: dom.heatmapRandomPad, metrics: dom.entropyRandomPad },
      recovered: { canvas: dom.canvasRecovered, heatmap: null, metrics: dom.entropyRecovered },
    };

    document.querySelectorAll("[data-heatmap]").forEach((btn) => {
      const key = btn.getAttribute("data-heatmap");
      if (!key) return;
      dom.heatmapButtons[key] = btn;
      btn.addEventListener("click", () => toggleHeatmap(key));
    });

    document.querySelectorAll("[data-heatmap-only]").forEach((btn) => {
      const key = btn.getAttribute("data-heatmap-only");
      if (!key) return;
      dom.heatmapOnlyButtons[key] = btn;
      btn.addEventListener("click", () => toggleHeatmapOnly(key));
    });

    document.querySelectorAll("[data-hist]").forEach((btn) => {
      const key = btn.getAttribute("data-hist");
      if (!key) return;
      btn.addEventListener("click", () => openHistogram(key));
    });

    document.querySelectorAll("[data-hist-mode]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const mode = btn.getAttribute("data-hist-mode");
        if (mode) {
          setHistogramMode(mode);
        }
      });
    });
  }

  function clearStatus() {
    dom.status.textContent = "";
  }

  function setStatus(message) {
    dom.status.textContent = message || "";
  }

  function setError(message) {
    dom.error.style.display = message ? "block" : "none";
    dom.error.textContent = message || "";
  }

  function base64FromUint8(array) {
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < array.length; i += chunk) {
      const slice = array.subarray(i, i + chunk);
      binary += String.fromCharCode.apply(null, slice);
    }
    return btoa(binary);
  }

  function fillRandomBytes(target) {
    if (window.crypto && window.crypto.getRandomValues) {
      const maxChunk = 65536;
      for (let offset = 0; offset < target.length; offset += maxChunk) {
        const view = target.subarray(offset, Math.min(offset + maxChunk, target.length));
        window.crypto.getRandomValues(view);
      }
      return;
    }
    for (let i = 0; i < target.length; i += 1) {
      target[i] = Math.floor(Math.random() * 256);
    }
  }

  function base64ToUint8(base64) {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function drawCanvas(canvas, imageData) {
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) return;
    if (!imageData) {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      return;
    }
    canvas.width = imageData.width;
    canvas.height = imageData.height;
    ctx.putImageData(imageData, 0, 0);
  }

  function clearHeatmap(canvas) {
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    }
    canvas.classList.remove("visible");
  }

  function convertRgbaBase64(base64, width, height) {
    const bytes = base64ToUint8(base64);
    return new ImageData(new Uint8ClampedArray(bytes.buffer, bytes.byteOffset, bytes.byteLength), width, height);
  }

  function buildImageDataFromBytes(bytes, width, height) {
    const total = width * height;
    const rgba = new Uint8ClampedArray(total * 4);
    for (let i = 0; i < total; i += 1) {
      const src = i * 4;
      rgba[src] = bytes[src];
      rgba[src + 1] = bytes[src + 1];
      rgba[src + 2] = bytes[src + 2];
      rgba[src + 3] = bytes[src + 3];
    }
    return new ImageData(rgba, width, height);
  }

  function clearPanels() {
    Object.keys(dom.panels).forEach((key) => {
      const panel = dom.panels[key];
      if (panel?.canvas) {
        const ctx = panel.canvas.getContext("2d");
        if (ctx) ctx.clearRect(0, 0, panel.canvas.width, panel.canvas.height);
        panel.canvas.classList.remove("panel-canvas--hidden");
      }
      if (panel?.heatmap) {
        clearHeatmap(panel.heatmap);
      }
      if (panel?.metrics) {
        panel.metrics.textContent = "Entropy pending.";
      }
      state.entropy[key] = null;
      state.heatmapVisible[key] = false;
      state.heatmapOnly[key] = false;
      const toggleBtn = dom.heatmapButtons[key];
      if (toggleBtn) {
        toggleBtn.classList.remove("active");
        toggleBtn.textContent = "Show heatmap";
      }
      updateHeatmapOnlyButton(key);
    });
  }

  function updateBadge() {
    const badge = dom.badge;
    if (!badge) return;
    badge.classList.remove("ok", "fail", "pending");
    if (state.verifyState === "verified") {
      badge.classList.add("ok");
      badge.textContent = "Signature verified";
    } else if (state.verifyState === "failed") {
      badge.classList.add("fail");
      badge.textContent = "Signature mismatch";
    } else {
      badge.classList.add("pending");
      badge.textContent = "Signature pending";
    }
  }

  function updateInfoPanel() {
    const result = state.encryptResult;
    dom.infoKem.textContent = result?.kem || "-";
    dom.infoSig.textContent = result?.sig || "-";
    dom.infoDemoSeed.textContent = result?.demoSeedUsed ? "enabled" : (dom.demoSeed.checked ? "enabled" : "disabled");
    if (result?.nonce) {
      try {
    state.wrongKeyBase64 = null;
    state.recoveredBase64 = null;
    state.entropy.wrongKey = null;
    state.entropy.recovered = null;
    renderEntropyReadout("wrongKey");
    renderEntropyReadout("recovered");
    setHeatmapVisibility("wrongKey", false, true);
    drawCanvas(dom.canvasWrong, null);
    drawCanvas(dom.canvasRecovered, null);
        dom.infoNonce.textContent = bytesToHex(base64ToUint8(result.nonce));
      } catch (err) {
        dom.infoNonce.textContent = "-";
      }
    } else {
      dom.infoNonce.textContent = "-";
    }
    dom.infoCtLen.textContent = result?.ciphertextLen ? `${result.ciphertextLen} bytes` : "-";
    dom.infoKemTime.textContent = typeof result?.kemEncapMs === "number" ? `${result.kemEncapMs.toFixed(2)} ms` : "-";
    dom.infoSymTime.textContent = typeof result?.symEncryptMs === "number" ? `${result.symEncryptMs.toFixed(2)} ms` : "-";
  }

  function formatNumber(value, digits = 2) {
    if (typeof value !== "number" || Number.isNaN(value)) {
      return "-";
    }
    return value.toFixed(digits);
  }

  function computeBlockStats(summary) {
    const blocks = summary?.blockEntropy;
    if (!Array.isArray(blocks) || !blocks.length) {
      return null;
    }
    let minVal = Infinity;
    let maxVal = -Infinity;
    for (let y = 0; y < blocks.length; y += 1) {
      const row = blocks[y];
      if (!Array.isArray(row)) continue;
      for (let x = 0; x < row.length; x += 1) {
        const val = row[x];
        if (typeof val !== "number" || Number.isNaN(val)) continue;
        if (val < minVal) minVal = val;
        if (val > maxVal) maxVal = val;
      }
    }
    if (!Number.isFinite(minVal) || !Number.isFinite(maxVal)) {
      return null;
    }
    return { min: minVal, max: maxVal };
  }

  function renderEntropyReadout(panelKey) {
    const panel = dom.panels[panelKey];
    if (!panel?.metrics) return;
    const summary = state.entropy[panelKey];
    if (!summary) {
      panel.metrics.textContent = "Entropy pending.";
      return;
    }
    const channels = summary.channelBits || {};
    const channelKeys = ["R", "G", "B"];
    if (Object.prototype.hasOwnProperty.call(channels, "A")) {
      channelKeys.push("A");
    }
    const channelLine = channelKeys
      .map((key) => `${key}: ${formatNumber(channels[key], 2)}`)
      .join(" | ");
    const blockStats = computeBlockStats(summary);
    const lines = [
      `<strong>Global:</strong> ${formatNumber(summary.bitsPerByteGlobal, 3)} b/B`,
      `<strong>RGB:</strong> ${formatNumber(summary.bitsPerPixelRGB, 3)} b/pixel`,
    ];
    if (typeof summary.bitsPerPixelRGBA === "number") {
      lines.push(`<strong>RGBA:</strong> ${formatNumber(summary.bitsPerPixelRGBA, 3)} b/pixel`);
    }
    lines.push(`<strong>Per-channel:</strong> ${channelLine}`);
    if (blockStats) {
      lines.push(`<strong>Heatmap:</strong> ${formatNumber(blockStats.min, 2)} to ${formatNumber(blockStats.max, 2)} b/B`);
    }
    panel.metrics.innerHTML = lines.join("<br />");
  }

  function updateEntropyPanels() {
    PANEL_KEYS.forEach((key) => {
      renderEntropyReadout(key);
      const wantVisible = Boolean(state.heatmapVisible[key]);
      const hasData = Boolean(state.entropy[key]?.blockEntropy);
      const shouldShow = wantVisible && hasData;
      setHeatmapVisibility(key, shouldShow, true);
    });
  }

  function updateHeatmapOnlyButton(panelKey) {
    const btn = dom.heatmapOnlyButtons[panelKey];
    if (!btn) return;
    const hasData = Boolean(state.entropy[panelKey]?.blockEntropy);
    const active = Boolean(state.heatmapOnly[panelKey] && state.heatmapVisible[panelKey] && hasData);
    btn.disabled = !hasData;
    btn.classList.toggle("active", active);
    btn.textContent = active ? "Show image" : "Heatmap only";
  }

  function setHeatmapVisibility(panelKey, visible, preserveState = false) {
    if (!preserveState) {
      state.heatmapVisible[panelKey] = visible;
      if (!visible) {
        state.heatmapOnly[panelKey] = false;
      }
    }
    const panel = dom.panels[panelKey];
    const heatmap = panel?.heatmap;
    const hasData = Boolean(state.entropy[panelKey]?.blockEntropy);
    if (heatmap) {
      if (visible && hasData) {
        const drawn = drawHeatmapForPanel(panelKey);
        if (!drawn) {
          clearHeatmap(heatmap);
        }
      } else {
        clearHeatmap(heatmap);
      }
    }
    if (panel?.canvas) {
      const hideCanvas = Boolean(state.heatmapOnly[panelKey] && state.heatmapVisible[panelKey] && hasData);
      panel.canvas.classList.toggle("panel-canvas--hidden", hideCanvas);
    }
    const btn = dom.heatmapButtons[panelKey];
    if (btn) {
      const requestVisible = Boolean(state.heatmapVisible[panelKey]);
      btn.classList.toggle("active", requestVisible);
      if (requestVisible && !hasData) {
        btn.textContent = "Heatmap pending";
      } else if (requestVisible && hasData) {
        btn.textContent = "Hide heatmap";
      } else {
        btn.textContent = "Show heatmap";
      }
    }
    updateHeatmapOnlyButton(panelKey);
  }

  function toggleHeatmap(panelKey) {
    const next = !state.heatmapVisible[panelKey];
    state.heatmapVisible[panelKey] = next;
    if (!next) {
      state.heatmapOnly[panelKey] = false;
    }
    setHeatmapVisibility(panelKey, next);
  }

  function toggleHeatmapOnly(panelKey) {
    const hasData = Boolean(state.entropy[panelKey]?.blockEntropy);
    if (!hasData) {
      state.heatmapOnly[panelKey] = false;
      updateHeatmapOnlyButton(panelKey);
      return;
    }
    const next = !state.heatmapOnly[panelKey];
    state.heatmapOnly[panelKey] = next;
    if (next && !state.heatmapVisible[panelKey]) {
      state.heatmapVisible[panelKey] = true;
    }
    setHeatmapVisibility(panelKey, state.heatmapVisible[panelKey]);
  }

  function drawHeatmapForPanel(panelKey) {
    const panel = dom.panels[panelKey];
    const summary = state.entropy[panelKey];
    if (!panel?.heatmap || !summary?.blockEntropy) {
      return false;
    }
    const baseCanvas = panel.canvas;
    const heatmap = panel.heatmap;
    heatmap.width = baseCanvas.width;
    heatmap.height = baseCanvas.height;
    const ctx = heatmap.getContext("2d");
    if (!ctx) {
      return false;
    }
    ctx.clearRect(0, 0, heatmap.width, heatmap.height);

    const blocks = summary.blockEntropy;
    if (!Array.isArray(blocks) || !blocks.length) {
      return false;
    }
    const tilesY = blocks.length;
    const tilesX = blocks[0]?.length || 0;
    if (!tilesX) {
      return false;
    }

    const tileWidth = heatmap.width / tilesX;
    const tileHeight = heatmap.height / tilesY;
    const clampMin = 5.0;
    const clampMax = 8.0;
    const denom = clampMax - clampMin || 1;

    for (let ty = 0; ty < tilesY; ty += 1) {
      const row = blocks[ty];
      if (!Array.isArray(row)) continue;
      for (let tx = 0; tx < tilesX; tx += 1) {
        const val = row[tx];
        if (typeof val !== "number" || Number.isNaN(val)) continue;
        const clamped = Math.min(clampMax, Math.max(clampMin, val));
        const t = (clamped - clampMin) / denom;
        const shade = Math.round(40 + t * 200);
        ctx.fillStyle = `rgba(${shade}, ${shade}, 255, 0.45)`;
        ctx.fillRect(tx * tileWidth, ty * tileHeight, tileWidth + 0.5, tileHeight + 0.5);
      }
    }
    heatmap.classList.add("visible");
    return true;
  }

  async function computeEntropyRemote({ base64, width, height, treatAsImage }) {
    const payload = {
      imageBytesBase64: base64,
      includeAlpha: state.includeAlpha,
      blockSize: 16,
    };
    if (!treatAsImage && width && height) {
      payload.width = width;
      payload.height = height;
    }
    const response = await fetch("/api/pqc/entropy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const json = await response.json();
    if (!response.ok || json.error) {
      throw new Error(json.error || `Entropy API failed (${response.status})`);
    }
    return json;
  }

  async function refreshEntropyForPanel(panelKey, options) {
    try {
      const summary = await computeEntropyRemote(options);
      state.entropy[panelKey] = summary;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      state.entropy[panelKey] = null;
    }
  }

  async function refreshAllEntropies() {
    if (!state.width || !state.height) {
      updateEntropyPanels();
      return;
    }
    setStatus(state.includeAlpha ? "Recomputing entropy (alpha included)..." : "Recomputing entropy (RGB)...");
    const tasks = [];
    if (state.originalBase64) {
      tasks.push(refreshEntropyForPanel("original", { base64: state.originalBase64, treatAsImage: true }));
    }
    if (state.encryptResult?.ciphertext) {
      tasks.push(
        refreshEntropyForPanel("ciphertext", {
          base64: state.encryptResult.ciphertext,
          width: state.encryptResult.width,
          height: state.encryptResult.height,
        })
      );
    }
    if (state.wrongKeyBase64) {
      tasks.push(
        refreshEntropyForPanel("wrongKey", {
          base64: state.wrongKeyBase64,
          width: state.width,
          height: state.height,
        })
      );
    }
    if (state.randomPadBase64) {
      tasks.push(
        refreshEntropyForPanel("randomPad", {
          base64: state.randomPadBase64,
          width: state.width,
          height: state.height,
        })
      );
    }
    if (state.recoveredBase64) {
      tasks.push(
        refreshEntropyForPanel("recovered", {
          base64: state.recoveredBase64,
          width: state.width,
          height: state.height,
        })
      );
    }
    await Promise.allSettled(tasks);
    updateEntropyPanels();
    if (dom.histModal.classList.contains("active")) {
      renderHistogram();
    }
    setStatus("Entropy refreshed.");
  }

  async function updateRandomPad() {
    const panel = dom.panels.randomPad;
    if (!state.width || !state.height || !panel?.canvas) {
      if (panel?.canvas) {
        const ctx = panel.canvas.getContext("2d");
        if (ctx) ctx.clearRect(0, 0, panel.canvas.width, panel.canvas.height);
      }
      state.randomPadBase64 = null;
      state.entropy.randomPad = null;
      renderEntropyReadout("randomPad");
      return;
    }
    const total = state.width * state.height;
    const rgba = new Uint8ClampedArray(total * 4);
    fillRandomBytes(rgba);
    for (let i = 0; i < total; i += 1) {
      rgba[i * 4 + 3] = 255;
    }
    const imageData = new ImageData(rgba, state.width, state.height);
    drawCanvas(panel.canvas, imageData);
    const raw = new Uint8Array(rgba.buffer.slice(0));
    state.randomPadBase64 = base64FromUint8(raw);
    try {
      const summary = await computeEntropyRemote({
        base64: state.randomPadBase64,
        width: state.width,
        height: state.height,
      });
      state.entropy.randomPad = summary;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      state.entropy.randomPad = null;
    }
    renderEntropyReadout("randomPad");
    setHeatmapVisibility("randomPad", state.heatmapVisible.randomPad, true);
    if (state.heatmapVisible.randomPad) {
      drawHeatmapForPanel("randomPad");
    }
  }

  async function selectDefaultImage() {
    try {
      const response = await fetch(DEFAULT_IMAGE_PATH, { cache: "no-cache" });
      if (!response.ok) {
        console.warn(`Default image fetch failed (${response.status}).`);
        return false;
      }
      const blob = await response.blob();
      const file = new File([blob], DEFAULT_IMAGE_NAME, { type: blob.type || "image/jpeg" });
      if (typeof DataTransfer !== "undefined") {
        try {
          const dataTransfer = new DataTransfer();
          dataTransfer.items.add(file);
          dom.fileInput.files = dataTransfer.files;
          await handleFileChange({ target: dom.fileInput });
          return true;
        } catch (assignErr) {
          console.warn("Failed to populate file input via DataTransfer.", assignErr);
        }
      }
      if (typeof ClipboardEvent !== "undefined") {
        try {
          const clipboardEvent = new ClipboardEvent("");
          const clipboardData = clipboardEvent.clipboardData;
          if (clipboardData) {
            clipboardData.items.add(file);
            dom.fileInput.files = clipboardData.files;
            await handleFileChange({ target: dom.fileInput });
            return true;
          }
        } catch (assignErr) {
          console.warn("Failed to populate file input via ClipboardEvent.", assignErr);
        }
      }
      await handleFileChange({ target: { files: [file] } });
      return true;
    } catch (err) {
      console.warn("Failed to preload default image.", err);
      return false;
    }
  }

  async function handleFileChange(event) {
    const file = event.target.files && event.target.files[0];
    clearStatus();
    setError("");
    state.encryptResult = null;
    state.verifyState = "pending";
    updateBadge();
    dom.btnDecrypt.disabled = true;
    dom.btnWrong.disabled = true;
    clearPanels();
    if (!file) {
      state.fileBytes = null;
      state.originalImage = null;
      state.width = 0;
      state.height = 0;
      state.originalBase64 = null;
      await updateRandomPad();
      updateInfoPanel();
      return;
    }
    try {
      const buffer = await file.arrayBuffer();
      state.fileBytes = new Uint8Array(buffer);
      state.originalBase64 = base64FromUint8(state.fileBytes);
      await renderImageFromFile(file);
      await refreshEntropyForPanel("original", { base64: state.originalBase64, treatAsImage: true });
      renderEntropyReadout("original");
      await updateRandomPad();
      setStatus("Image loaded. Ready to encrypt.");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  function renderImageFromFile(file) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const image = new Image();
      image.onload = () => {
        URL.revokeObjectURL(url);
        const canvas = document.createElement("canvas");
        canvas.width = image.width;
        canvas.height = image.height;
        const ctx = canvas.getContext("2d", { willReadFrequently: true });
        if (!ctx) {
          reject(new Error("Unable to render canvas context."));
          return;
        }
        ctx.drawImage(image, 0, 0);
        const imageData = ctx.getImageData(0, 0, image.width, image.height);
        state.originalImage = imageData;
        state.width = image.width;
        state.height = image.height;
        drawCanvas(dom.canvasOriginal, imageData);
        resolve();
      };
      image.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error("Failed to load image."));
      };
      image.src = url;
    });
  }

  async function encryptImage() {
    if (!state.fileBytes || !state.originalImage) {
      setError("Please choose an image first.");
      return;
    }
    clearStatus();
    setError("");
    dom.btnEncrypt.disabled = true;
    dom.btnDecrypt.disabled = true;
    dom.btnWrong.disabled = true;
    setStatus("Deriving shared secret...");
    state.verifyState = "pending";
    updateBadge();
    try {
      const payload = {
        kem: dom.kemSelect.value,
        sig: dom.sigSelect.value,
        imageBytesBase64: state.originalBase64,
        useDemoSeed: !!dom.demoSeed.checked,
        includeAlpha: state.includeAlpha,
      };
      const response = await fetch("/api/pqc/encrypt-image", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const json = await response.json();
      if (!response.ok || json.error) {
        throw new Error(json.error || `Encrypt failed (${response.status})`);
      }
      state.encryptResult = json;
      updateInfoPanel();
      if (json.width && json.height) {
        state.width = json.width;
        state.height = json.height;
      }
      const cipherBytes = base64ToUint8(json.ciphertext);
      const cipherImage = buildImageDataFromBytes(cipherBytes, json.width, json.height);
      drawCanvas(dom.canvasCipher, cipherImage);
      state.entropy.original = json.entropy?.original || state.entropy.original;
      state.entropy.ciphertext = json.entropy?.ciphertext || null;
      updateEntropyPanels();
      if (state.heatmapVisible.ciphertext) {
        drawHeatmapForPanel("ciphertext");
      }
      await updateRandomPad();
      dom.btnDecrypt.disabled = false;
      dom.btnWrong.disabled = false;
      setStatus("Encryption complete.");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      state.encryptResult = null;
      state.entropy.ciphertext = null;
      renderEntropyReadout("ciphertext");
      setHeatmapVisibility("ciphertext", false, true);
      drawCanvas(dom.canvasCipher, null);
      updateInfoPanel();
    } finally {
      dom.btnEncrypt.disabled = false;
    }
  }

  async function decryptImage(wrongKey) {
    if (!state.encryptResult) {
      setError("Encrypt an image first.");
      return;
    }
    clearStatus();
    setError("");
    dom.btnDecrypt.disabled = true;
    dom.btnWrong.disabled = true;
    setStatus(wrongKey ? "Trying wrong key..." : "Decapsulating ciphertext...");
    try {
      const payload = {
        kem: state.encryptResult.kem || dom.kemSelect.value,
        sig: state.encryptResult.sig || dom.sigSelect.value,
        kemSecretKey: state.encryptResult.kemSecretKey,
        kemCiphertext: state.encryptResult.kemCiphertext,
        nonce: state.encryptResult.nonce,
        width: state.encryptResult.width,
        height: state.encryptResult.height,
        permMeta: state.encryptResult.permMeta,
        ciphertext: state.encryptResult.ciphertext,
        signature: state.encryptResult.signature,
        sigPublicKey: state.encryptResult.sigPublicKey,
        wrongKey,
        includeAlpha: state.includeAlpha,
      };
      const response = await fetch("/api/pqc/decrypt-image", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const json = await response.json();
      if (!response.ok || json.error) {
        throw new Error(json.error || `Decrypt failed (${response.status})`);
      }
      if (wrongKey) {
        state.wrongKeyBase64 = json.wrongKeyPreviewBytes || null;
        if (state.wrongKeyBase64) {
          const preview = convertRgbaBase64(state.wrongKeyBase64, state.encryptResult.width, state.encryptResult.height);
          drawCanvas(dom.canvasWrong, preview);
          state.entropy.wrongKey = json.entropy?.wrongKey || null;
          renderEntropyReadout("wrongKey");
          setHeatmapVisibility("wrongKey", state.heatmapVisible.wrongKey, true);
          if (state.heatmapVisible.wrongKey) {
            drawHeatmapForPanel("wrongKey");
          }
        }
        setStatus("Wrong key preview updated.");
      } else {
        state.recoveredBase64 = json.recoveredImageBytes || null;
        if (state.recoveredBase64) {
          const recovered = convertRgbaBase64(state.recoveredBase64, state.encryptResult.width, state.encryptResult.height);
          state.recoveredImage = recovered;
          drawCanvas(dom.canvasRecovered, recovered);
          openModal();
        }
        const verifyOk = json.verifyOk;
        if (verifyOk === true) {
          state.verifyState = "verified";
        } else if (verifyOk === false) {
          state.verifyState = "failed";
        } else {
          state.verifyState = "pending";
        }
        updateBadge();
        state.entropy.recovered = json.entropy?.recovered || null;
        renderEntropyReadout("recovered");
        setStatus("Image recovered.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      if (!wrongKey) {
        state.verifyState = "failed";
        updateBadge();
      }
    } finally {
      dom.btnDecrypt.disabled = false;
      dom.btnWrong.disabled = false;
    }
  }

  function openModal() {
    dom.modal.classList.add("active");
  }

  function closeModal() {
    dom.modal.classList.remove("active");
  }

  function openHistogram(panelKey) {
    const summary = state.entropy[panelKey];
    if (!summary?.histograms) {
      setError("Histogram data unavailable yet.");
      return;
    }
    state.histogramPanel = panelKey;
    dom.histModal.classList.add("active");
    setHistogramMode(panelKey);
  }

  function closeHistogram() {
    dom.histModal.classList.remove("active");
  }

  function setHistogramMode(panelKey) {
    if (!state.entropy[panelKey]?.histograms) {
      return;
    }
    state.histogramPanel = panelKey;
    document.querySelectorAll("[data-hist-mode]").forEach((btn) => {
      const mode = btn.getAttribute("data-hist-mode");
      btn.classList.toggle("active", mode === panelKey);
    });
    renderHistogram();
  }

  function renderHistogram() {
    const summary = state.entropy[state.histogramPanel];
    if (!summary?.histograms) return;
    drawHistogramChannel(dom.histCanvasR, summary.histograms.R, "rgba(255,99,132,0.8)");
    drawHistogramChannel(dom.histCanvasG, summary.histograms.G, "rgba(75,192,192,0.8)");
    drawHistogramChannel(dom.histCanvasB, summary.histograms.B, "rgba(54,162,235,0.8)");
  }

  function drawHistogramChannel(canvas, bins, color) {
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const width = canvas.width;
    const height = canvas.height;
    ctx.clearRect(0, 0, width, height);
    if (!Array.isArray(bins) || !bins.length) return;
    const max = bins.reduce((acc, v) => (v > acc ? v : acc), 0);
    if (!max) return;
    const barWidth = width / bins.length;
    ctx.fillStyle = color;
    for (let i = 0; i < bins.length; i += 1) {
      const value = bins[i];
      const norm = value / max;
      const barHeight = Math.max(1, norm * (height - 8));
      const x = i * barWidth;
      const y = height - barHeight;
      ctx.fillRect(x, y, Math.max(1, barWidth - 0.5), barHeight);
    }
    ctx.strokeStyle = "rgba(255,255,255,0.25)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(0, height - 0.5);
    ctx.lineTo(width, height - 0.5);
    ctx.stroke();
  }

  function wireEvents() {
    dom.fileInput.addEventListener("change", handleFileChange);
    dom.btnEncrypt.addEventListener("click", (event) => {
      event.preventDefault();
      encryptImage();
    });
    dom.btnDecrypt.addEventListener("click", (event) => {
      event.preventDefault();
      decryptImage(false);
    });
    dom.btnWrong.addEventListener("click", (event) => {
      event.preventDefault();
      decryptImage(true);
    });
    dom.modalClose.addEventListener("click", () => closeModal());
    dom.modal.addEventListener("click", (event) => {
      if (event.target === dom.modal) {
        closeModal();
      }
    });
    dom.histClose.addEventListener("click", () => closeHistogram());
    dom.histModal.addEventListener("click", (event) => {
      if (event.target === dom.histModal) {
        closeHistogram();
      }
    });
    dom.includeAlpha.addEventListener("change", async () => {
      state.includeAlpha = !!dom.includeAlpha.checked;
      await refreshAllEntropies();
    });
  }

  async function bootstrap() {
    initDom();
    wireEvents();
    updateBadge();
    updateInfoPanel();
    updateEntropyPanels();
    const loaded = await selectDefaultImage();
    if (!loaded) {
      await updateRandomPad();
    }
  }

  function start() {
    bootstrap().catch((err) => {
      setError(err instanceof Error ? err.message : String(err));
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
