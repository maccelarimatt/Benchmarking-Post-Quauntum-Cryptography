(function () {
  "use strict";

  const state = {
    fileBytes: null,
    originalImage: null,
    width: 0,
    height: 0,
    encryptResult: null,
    verifyState: "pending",
    recoveredImage: null,
  };

  const dom = {};

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
    dom.modal = qs("recovered-modal");
    dom.modalClose = qs("modal-close");
    dom.badge = qs("badge-verify");
    dom.infoKem = qs("info-kem");
    dom.infoSig = qs("info-sig");
    dom.infoNonce = qs("info-nonce");
    dom.infoCtLen = qs("info-ctlen");
    dom.infoKemTime = qs("info-kemtime");
    dom.infoSymTime = qs("info-symtime");
    dom.infoDemoSeed = qs("info-demoseed");
  }

  function clearStatus() {
    dom.status.textContent = "";
    dom.error.style.display = "none";
    dom.error.textContent = "";
  }

  function setStatus(message) {
    dom.status.textContent = message || "";
  }

  function setError(message) {
    dom.error.style.display = message ? "block" : "none";
    dom.error.textContent = message || "";
  }

  function drawCanvas(canvas, imageData) {
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) {
      return;
    }
    if (!imageData) {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      return;
    }
    canvas.width = imageData.width;
    canvas.height = imageData.height;
    ctx.putImageData(imageData, 0, 0);
  }

  function clearPanels() {
    [dom.canvasCipher, dom.canvasWrong, dom.canvasRandom, dom.canvasRecovered].forEach((canvas) => {
      const ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
      }
    });
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

  function buildImageDataFromBytes(bytes, width, height) {
    const total = width * height;
    const rgba = new Uint8ClampedArray(total * 4);
    for (let i = 0; i < total; i += 1) {
      const src = i * 4;
      const dst = i * 4;
      rgba[dst] = bytes[src] ?? 0;
      rgba[dst + 1] = bytes[src + 1] ?? 0;
      rgba[dst + 2] = bytes[src + 2] ?? 0;
      rgba[dst + 3] = 255;
    }
    return new ImageData(rgba, width, height);
  }

  function convertRgbaBase64(base64, width, height) {
    const bytes = base64ToUint8(base64);
    return new ImageData(new Uint8ClampedArray(bytes.buffer, bytes.byteOffset, bytes.byteLength), width, height);
  }

  function updateRandomPad() {
    if (!state.width || !state.height) {
      const ctx = dom.canvasRandom.getContext("2d");
      if (ctx) ctx.clearRect(0, 0, dom.canvasRandom.width, dom.canvasRandom.height);
      return;
    }
    const total = state.width * state.height;
    const rgb = new Uint8Array(total * 3);
    fillRandomBytes(rgb);
    const rgba = new Uint8ClampedArray(total * 4);
    for (let i = 0; i < total; i += 1) {
      const src = i * 3;
      const dst = i * 4;
      rgba[dst] = rgb[src];
      rgba[dst + 1] = rgb[src + 1];
      rgba[dst + 2] = rgb[src + 2];
      rgba[dst + 3] = 255;
    }
    const imageData = new ImageData(rgba, state.width, state.height);
    drawCanvas(dom.canvasRandom, imageData);
  }
  async function handleFileChange(event) {
    const file = event.target.files && event.target.files[0];
    clearStatus();
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
      drawCanvas(dom.canvasOriginal, null);
      updateMetrics();
      return;
    }
    try {
      const buffer = await file.arrayBuffer();
      state.fileBytes = new Uint8Array(buffer);
      await renderImageFromFile(file);
      updateRandomPad();
      setStatus("Image loaded. Ready to encrypt.");
      setError("");
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
        const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
        state.originalImage = data;
        state.width = data.width;
        state.height = data.height;
        drawCanvas(dom.canvasOriginal, data);
        resolve();
      };
      image.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error("Unable to read image file."));
      };
      image.src = url;
    });
  }

  function updateMetrics() {
    const result = state.encryptResult;
    dom.infoKem.textContent = result?.kem || "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â";
    dom.infoSig.textContent = result?.sig || "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â";
    dom.infoDemoSeed.textContent = state.encryptResult?.demoSeedUsed ? "enabled" : (dom.demoSeed.checked ? "enabled" : "disabled");
    if (result?.nonce) {
      try {
        dom.infoNonce.textContent = bytesToHex(base64ToUint8(result.nonce));
      } catch (err) {
        dom.infoNonce.textContent = "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â";
      }
    } else {
      dom.infoNonce.textContent = "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â";
    }
    dom.infoCtLen.textContent = result?.ciphertextLen ? `${result.ciphertextLen} bytes` : "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â";
    dom.infoKemTime.textContent = typeof result?.kemEncapMs === "number" ? `${result.kemEncapMs.toFixed(2)} ms` : "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â";
    dom.infoSymTime.textContent = typeof result?.symEncryptMs === "number" ? `${result.symEncryptMs.toFixed(2)} ms` : "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â";
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

  async function encryptImage() {
    if (!state.fileBytes || !state.originalImage) {
      setError("Please choose an image first.");
      return;
    }
    clearStatus();
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
        imageBytesBase64: base64FromUint8(state.fileBytes),
        useDemoSeed: !!dom.demoSeed.checked,
      };
      const response = await fetch("/api/pqc/encrypt-image", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const json = await response.json();
      if (!response.ok || json.error) {
        throw new Error(json.error || `Encryption failed (${response.status})`);
      }
      state.encryptResult = json;
      const cipherBytes = base64ToUint8(json.ciphertext);
      const cipherImage = buildImageDataFromBytes(cipherBytes, json.width, json.height);
      drawCanvas(dom.canvasCipher, cipherImage);
      updateRandomPad();
      updateMetrics();
      dom.btnDecrypt.disabled = false;
      dom.btnWrong.disabled = false;
      setStatus("Encryption complete.");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      state.encryptResult = null;
      updateMetrics();
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
        const preview = convertRgbaBase64(json.wrongKeyPreviewBytes, state.encryptResult.width, state.encryptResult.height);
        drawCanvas(dom.canvasWrong, preview);
        setStatus("Wrong key preview updated.");
      } else {
        const recovered = convertRgbaBase64(json.recoveredImageBytes, state.encryptResult.width, state.encryptResult.height);
        state.recoveredImage = recovered;
        drawCanvas(dom.canvasRecovered, recovered);
        openModal();
        const verifyOk = json.verifyOk;
        if (verifyOk === true) {
          state.verifyState = "verified";
        } else if (verifyOk === false) {
          state.verifyState = "failed";
        } else {
          state.verifyState = "pending";
        }
        updateBadge();
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
  }

  function bootstrap() {
    initDom();
    wireEvents();
    updateMetrics();
    updateBadge();
    updateRandomPad();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }
})();

