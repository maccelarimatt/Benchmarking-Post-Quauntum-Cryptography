/* Helper to render Chart.js graphs embedded in LLM output.
 *
 * The LLM can emit markup like:
 * <figure data-chart='{"type":"bar","title":"Runtime","labels":["Kyber","Falcon"],"datasets":[{"label":"Sign","data":[1.2,2.3]}]}'>
 *   <figcaption>Sign latency comparison.</figcaption>
 * </figure>
 *
 * This script finds those figures and renders the requested chart.
 */
(function () {
  const MAX_RETRIES = 20;
  const RETRY_DELAY_MS = 150;
  const palette = [
    { bg: "rgba(56,189,248,1)", border: "rgba(56,189,248,1)" }, // sky-400
    { bg: "rgba(248,113,113,1)", border: "rgba(248,113,113,1)" }, // red-400
    { bg: "rgba(74,222,128,1)", border: "rgba(74,222,128,1)" }, // green-400
    { bg: "rgba(251,191,36,1)", border: "rgba(251,191,36,1)" }, // amber-400
    { bg: "rgba(129,140,248,1)", border: "rgba(129,140,248,1)" }, // indigo-400
    { bg: "rgba(244,114,182,1)", border: "rgba(244,114,182,1)" }, // pink-400
    { bg: "rgba(45,212,191,1)", border: "rgba(45,212,191,1)" }, // teal-400
    { bg: "rgba(196,181,253,1)", border: "rgba(196,181,253,1)" }, // violet-300
  ];

  function ensureStyle() {
    if (document.getElementById("llm-chart-style")) {
      return;
    }
    const style = document.createElement("style");
    style.id = "llm-chart-style";
    style.textContent = [
      "figure[data-chart] { margin: 1.25rem 0; padding: 0.5rem 0; }",
      "figure[data-chart] canvas.llm-chart-canvas { width: 100% !important; height: auto !important; max-height: 360px; }",
      "figure[data-chart] pre.llm-chart-error { background: rgba(248,113,113,0.14); color: #fecaca; padding: .55rem .75rem; border-radius: .5rem; margin: .5rem 0; font-size: .85rem; overflow: auto; }",
    ].join("\n");
    document.head.appendChild(style);
  }

  function parseColorTuple(colorStr) {
    if (typeof colorStr !== "string" || !colorStr.trim()) {
      return [226, 232, 240]; // slate-100 fallback
    }
    const str = colorStr.trim();
    if (str.startsWith("rgb")) {
      const nums = str
        .replace(/rgba?|\(|\)|\s/g, "")
        .split(",")
        .map((v) => parseFloat(v));
      if (nums.length >= 3 && nums.every((n) => Number.isFinite(n))) {
        return nums.slice(0, 3);
      }
    } else if (str.startsWith("#")) {
      let hex = str.slice(1);
      if (hex.length === 3) {
        hex = hex
          .split("")
          .map((c) => c + c)
          .join("");
      }
      if (hex.length >= 6) {
        const r = parseInt(hex.slice(0, 2), 16);
        const g = parseInt(hex.slice(2, 4), 16);
        const b = parseInt(hex.slice(4, 6), 16);
        if ([r, g, b].every((n) => Number.isFinite(n))) {
          return [r, g, b];
        }
      }
    }
    return [226, 232, 240];
  }

  function luminance([r, g, b]) {
    const toLin = (v) => {
      const c = v / 255;
      return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    };
    const rl = toLin(r);
    const gl = toLin(g);
    const bl = toLin(b);
    return 0.2126 * rl + 0.7152 * gl + 0.0722 * bl;
  }

  function rgba(tuple, alpha) {
    const [r, g, b] = tuple;
    return `rgba(${Math.round(r)}, ${Math.round(g)}, ${Math.round(b)}, ${alpha})`;
  }

  function deepClone(value) {
    if (value === null || typeof value !== "object") {
      return value;
    }
    if (Array.isArray(value)) {
      return value.map((item) => deepClone(item));
    }
    const out = {};
    Object.keys(value).forEach((key) => {
      out[key] = deepClone(value[key]);
    });
    return out;
  }

  function deepMerge(target, source) {
    if (source === null || typeof source !== "object") {
      return target;
    }
    Object.keys(source).forEach((key) => {
      const value = source[key];
      if (value && typeof value === "object" && !Array.isArray(value)) {
        if (!target[key] || typeof target[key] !== "object" || Array.isArray(target[key])) {
          target[key] = {};
        }
        deepMerge(target[key], value);
      } else if (Array.isArray(value)) {
        target[key] = value.map((item) => deepClone(item));
      } else {
        target[key] = value;
      }
    });
    return target;
  }

  function cleanNumber(value) {
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
    if (typeof value === "string") {
      const parsed = Number(value.trim());
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
    return null;
  }

  function removeError(fig) {
    const prevError = fig.querySelector("pre.llm-chart-error");
    if (prevError) {
      prevError.remove();
    }
  }

  function showError(fig, message) {
    if (!fig) return;
    const existingCanvas = fig.querySelector("canvas.llm-chart-canvas");
    if (existingCanvas) {
      if (existingCanvas._llmChartInstance) {
        try {
          existingCanvas._llmChartInstance.destroy();
        } catch (_) {
          /* ignore */
        }
      }
      existingCanvas.remove();
    }
    let pre = fig.querySelector("pre.llm-chart-error");
    if (!pre) {
      pre = document.createElement("pre");
      pre.className = "llm-chart-error";
      fig.insertBefore(pre, fig.firstChild || null);
    }
    pre.textContent = String(message);
  }

  function getCanvas(fig) {
    let canvas = fig.querySelector("canvas.llm-chart-canvas");
    if (canvas) {
      return canvas;
    }
    canvas = document.createElement("canvas");
    canvas.className = "llm-chart-canvas";
    const caption = fig.querySelector("figcaption");
    if (caption) {
      fig.insertBefore(canvas, caption);
    } else {
      fig.appendChild(canvas);
    }
    return canvas;
  }

  function computeTheme() {
    const bodyStyles = window.getComputedStyle(document.body);
    const bgTuple = parseColorTuple(bodyStyles.backgroundColor);
    const darkMode = luminance(bgTuple) < 0.5;
    if (darkMode) {
      return {
        mode: "dark",
        text: "#f8fafc",
        grid: "rgba(148,163,184,0.25)",
        border: "rgba(148,163,184,0.35)",
        tooltipBg: "#0f172a",
        tooltipColor: "#e2e8f0",
      };
    }
    return {
      mode: "light",
      text: "#1e293b",
      grid: "rgba(148,163,184,0.25)",
      border: "rgba(71,85,105,0.35)",
      tooltipBg: "#f8fafc",
      tooltipColor: "#1e293b",
    };
  }

  function buildChart(fig, cfg, paletteOffset, theme) {
    const allowedTypes = ["bar", "line", "radar", "polararea", "doughnut"];
    let type = typeof cfg.type === "string" ? cfg.type.toLowerCase() : "bar";
    if (!allowedTypes.includes(type)) {
      type = "bar";
    }

    const labels = Array.isArray(cfg.labels)
      ? cfg.labels.map((label) => String(label))
      : [];

    const datasetsInput = Array.isArray(cfg.datasets) ? cfg.datasets : [];
    const datasets = [];
    datasetsInput.forEach((ds, idx) => {
      const rawData = Array.isArray(ds.data) ? ds.data : [];
      const data = rawData.map((value) => {
        const num = cleanNumber(value);
        return num === null ? null : num;
      });
      if (!data.length || data.every((v) => v === null)) {
        return;
      }
      const paletteEntry = palette[(paletteOffset + idx) % palette.length];
      const dataset = {
        label:
          typeof ds.label === "string" && ds.label.trim()
            ? ds.label.trim()
            : `Series ${idx + 1}`,
        data,
      };
      dataset.backgroundColor =
        typeof ds.backgroundColor === "string" && ds.backgroundColor.trim()
          ? ds.backgroundColor
          : type === "line"
          ? paletteEntry.border
          : paletteEntry.bg;
      dataset.borderColor =
        typeof ds.borderColor === "string" && ds.borderColor.trim()
          ? ds.borderColor
          : paletteEntry.border;
      dataset.borderWidth =
        typeof ds.borderWidth === "number" && Number.isFinite(ds.borderWidth)
          ? ds.borderWidth
          : type === "line"
          ? 2
          : 1;
      if (typeof ds.fill === "boolean") {
        dataset.fill = ds.fill;
      } else {
        dataset.fill = type === "line" ? false : true;
      }
      if (typeof ds.tension === "number" && Number.isFinite(ds.tension)) {
        dataset.tension = ds.tension;
      } else if (type === "line") {
        dataset.tension = 0.32;
      }
      if (typeof ds.type === "string" && ds.type.trim()) {
        dataset.type = ds.type.trim();
      }
      if (ds.stack) {
        dataset.stack = ds.stack;
      }
      if (ds.pointRadius !== undefined) {
        dataset.pointRadius = ds.pointRadius;
      }
      datasets.push(dataset);
    });

    if (!datasets.length) {
      showError(fig, "Chart definition missing usable datasets.");
      return;
    }

    const data = { labels, datasets };
    const titleText =
      typeof cfg.title === "string" && cfg.title.trim() ? cfg.title.trim() : "";

    const isLineChart = type === "line";
    const legendBoxSize = isLineChart ? 12 : 14;
    const legendPointStyle = isLineChart ? "line" : "circle";
    const baseOptions = {
      responsive: true,
      maintainAspectRatio: false,
      layout: { padding: { top: 8, right: 12, bottom: 8, left: 12 } },
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          display: cfg.legend === false ? false : datasets.length > 1,
          position:
            cfg.legend && typeof cfg.legend === "object" && typeof cfg.legend.position === "string"
              ? cfg.legend.position
              : "top",
          labels: {
            color: theme.text,
            usePointStyle: true,
            pointStyle: legendPointStyle,
            boxWidth: legendBoxSize,
            boxHeight: legendBoxSize,
            font: { size: 12 },
          },
        },
        title: {
          display: Boolean(titleText),
          text: titleText,
          color: theme.text,
          font: { size: 16, weight: 600 },
        },
        tooltip: {
          backgroundColor: theme.tooltipBg,
          titleColor: theme.tooltipColor,
          bodyColor: theme.tooltipColor,
          borderColor: theme.border,
          borderWidth: 1,
        },
      },
    };

    if (type === "bar" || type === "line") {
      baseOptions.scales = {
        x: {
          stacked: Boolean(cfg.stacked),
          ticks: { color: theme.text },
          grid: { color: theme.grid, borderColor: theme.border },
        },
        y: {
          stacked: Boolean(cfg.stacked),
          ticks: { color: theme.text },
          grid: { color: theme.grid, borderColor: theme.border },
          beginAtZero: cfg.beginAtZero !== false,
        },
      };
      if (cfg.y && typeof cfg.y === "object") {
        if (typeof cfg.y.title === "string" && cfg.y.title.trim()) {
          baseOptions.scales.y.title = {
            display: true,
            text: cfg.y.title.trim(),
            color: theme.text,
            font: { size: 13, weight: 600 },
          };
        }
        if (typeof cfg.y.max === "number" && Number.isFinite(cfg.y.max)) {
          baseOptions.scales.y.suggestedMax = cfg.y.max;
        }
        if (typeof cfg.y.min === "number" && Number.isFinite(cfg.y.min)) {
          baseOptions.scales.y.suggestedMin = cfg.y.min;
        }
      }
      if (cfg.x && typeof cfg.x === "object") {
        if (typeof cfg.x.title === "string" && cfg.x.title.trim()) {
          baseOptions.scales.x.title = {
            display: true,
            text: cfg.x.title.trim(),
            color: theme.text,
            font: { size: 13, weight: 600 },
          };
        }
      }
    } else if (type === "radar") {
      baseOptions.scales = {
        r: {
          angleLines: { color: theme.grid },
          grid: { color: theme.grid },
          pointLabels: { color: theme.text, font: { size: 12 } },
          ticks: { color: theme.text, backdropColor: "transparent" },
        },
      };
    }

    const userOptions =
      cfg.options && typeof cfg.options === "object" ? cfg.options : null;
    let options = deepClone(baseOptions);
    if (userOptions) {
      options = deepMerge(options, userOptions);
    }

    const canvas = getCanvas(fig);
    removeError(fig);
    if (canvas._llmChartInstance) {
      try {
        canvas._llmChartInstance.destroy();
      } catch (_) {
        /* ignore */
      }
    }
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      showError(fig, "Unable to allocate drawing context for chart.");
      return;
    }
    const chart = new window.Chart(ctx, {
      type,
      data,
      options,
    });
    canvas._llmChartInstance = chart;
    fig.__llmChartInstance = chart;
  }

  function renderInternal(root, attempt) {
    if (!root) {
      return;
    }
    ensureStyle();
    if (!window.Chart || typeof window.Chart !== "function") {
      if (attempt >= MAX_RETRIES) {
        return;
      }
      window.setTimeout(() => renderInternal(root, attempt + 1), RETRY_DELAY_MS);
      return;
    }
    const figures = root.querySelectorAll("figure[data-chart]");
    if (!figures.length) {
      return;
    }
    const theme = computeTheme();
    figures.forEach((fig, idx) => {
      const raw = fig.getAttribute("data-chart");
      if (!raw || !raw.trim()) {
        showError(fig, "Missing data-chart JSON payload.");
        return;
      }
      if (fig.__llmChartRaw === raw && fig.__llmChartMode === theme.mode) {
        return;
      }
      try {
        const cfg = JSON.parse(raw);
        buildChart(fig, cfg, idx, theme);
        fig.__llmChartRaw = raw;
        fig.__llmChartMode = theme.mode;
      } catch (err) {
        showError(fig, `Invalid chart definition: ${String(err)}`);
      }
    });
  }

  window.renderLLMCharts = function (root) {
    renderInternal(root, 0);
  };
})();
