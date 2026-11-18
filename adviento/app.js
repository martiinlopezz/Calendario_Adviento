const CLAVE = "adviento-abiertas";
const CLAVE_INTRO = "adviento-intro";
const CLAVE_AVISO = "adviento-aviso";
const CLAVE_SECRETA = "adviento-clave";
const MESES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
  "agosto", "septiembre", "octubre", "noviembre", "diciembre"];

const params = new URLSearchParams(location.search);
const grid = document.getElementById("grid");
const visor = document.getElementById("visor");
const contenidoEl = document.getElementById("contenido");
const toastEl = document.getElementById("toast");

document.body.dataset.tema = CONFIG.tema || "noche";
document.body.dataset.color = CONFIG.color || "rojo";
document.getElementById("titulo").textContent = CONFIG.titulo;
document.getElementById("subtitulo").textContent = CONFIG.subtitulo;
document.getElementById("intro-para").textContent = `Para ${CONFIG.nombre} ❤️`;

// ---------- Utilidades ----------
function leer(clave, defecto) {
  try {
    const v = localStorage.getItem(clave);
    return v === null ? defecto : JSON.parse(v);
  } catch {
    return defecto;
  }
}
function guardar(clave, valor) {
  try { localStorage.setItem(clave, JSON.stringify(valor)); } catch { /* sin almacenamiento */ }
}

// Pruebas: ?reset borra el progreso y la clave, ?hoy=2026-12-05 simula la fecha,
// ?intro fuerza el sobre, ?prueba muestra el panel de pruebas
if (params.has("reset")) {
  [CLAVE, CLAVE_INTRO, CLAVE_AVISO, CLAVE_SECRETA].forEach((k) => {
    try { localStorage.removeItem(k); } catch { /* nada */ }
  });
}

let fechaPrueba = params.get("hoy");

function hoy() {
  if (fechaPrueba) {
    const [y, m, d] = fechaPrueba.split("-").map(Number);
    return new Date(y, m - 1, d);
  }
  const n = new Date();
  return new Date(n.getFullYear(), n.getMonth(), n.getDate());
}

function desbloqueada(dia) {
  return hoy() >= new Date(CONFIG.anio, CONFIG.mes - 1, dia);
}

// Orden barajado pero estable (misma semilla = mismo orden siempre)
function mulberry32(a) {
  return function () {
    a |= 0;
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function orden() {
  const dias = Array.from({ length: CONFIG.dias }, (_, i) => i + 1);
  const r = mulberry32(CONFIG.semilla ?? 24);
  for (let i = dias.length - 1; i > 0; i--) {
    const j = Math.floor(r() * (i + 1));
    [dias[i], dias[j]] = [dias[j], dias[i]];
  }
  return dias;
}

function el(tag, props = {}, padre = contenidoEl) {
  const e = Object.assign(document.createElement(tag), props);
  padre.appendChild(e);
  return e;
}
const nuevo = (tag, props) => Object.assign(document.createElement(tag), props);

function toast(msg) {
  toastEl.textContent = msg;
  toastEl.classList.add("visible");
  setTimeout(() => toastEl.classList.remove("visible"), 2400);
}

// ---------- Descifrado ----------
const ENC = new TextEncoder();
let llave = null;   // CryptoKey AES-GCM
let ICONOS = {};    // { "1": "📷", ... } (viene cifrado en datos/indice.bin)

// Tiene que coincidir con normalizar() de cifrar.py
function normalizar(s) {
  return s.normalize("NFC").trim().toLowerCase().replace(/\s+/g, "-");
}

function desdeBase64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function derivarLlave(clave, meta) {
  const base = await crypto.subtle.importKey("raw", ENC.encode(normalizar(clave)), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: desdeBase64(meta.sal), iterations: meta.iter, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

async function descargar(ruta, revalidar = false) {
  const r = await fetch(ruta, revalidar ? { cache: "no-cache" } : undefined);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

async function descifrar(bytes) {
  const iv = bytes.slice(0, 12);
  const datos = bytes.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, llave, datos));
}

async function descifrarJSON(ruta) {
  const claro = await descifrar(await descargar(ruta, true));
  return JSON.parse(new TextDecoder().decode(claro));
}

// true = clave correcta; false = clave incorrecta; lanza error si es un fallo de red
async function intentarClave(clave, meta) {
  llave = await derivarLlave(clave, meta);
  try {
    ICONOS = await descifrarJSON("datos/indice.bin");
    return true;
  } catch (e) {
    llave = null;
    if (e.name === "OperationError") return false;
    throw e;
  }
}

function pedirClave(meta) {
  return new Promise((resolver) => {
    const caja = document.getElementById("clave");
    const input = document.getElementById("clave-input");
    const error = document.getElementById("clave-error");
    const boton = document.getElementById("clave-ok");
    caja.hidden = false;
    setTimeout(() => input.focus(), 100);

    async function probar() {
      const valor = input.value;
      if (!normalizar(valor)) return;
      boton.disabled = true;
      error.hidden = true;
      try {
        if (await intentarClave(valor, meta)) {
          guardar(CLAVE_SECRETA, valor);
          caja.hidden = true;
          resolver();
          return;
        }
        error.textContent = "Esa clave no es correcta. Prueba otra vez.";
      } catch {
        error.textContent = "No se ha podido comprobar. Revisa tu conexión.";
      }
      error.hidden = false;
      boton.disabled = false;
    }
    boton.addEventListener("click", probar);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") probar(); });
  });
}

async function abrirCandado() {
  const meta = await (await fetch("datos/meta.json", { cache: "no-cache" })).json();

  // 1) clave en el enlace (#clave), 2) clave guardada en el móvil, 3) pedirla
  const intentos = [];
  if (location.hash.length > 1) {
    let c = location.hash.slice(1);
    try { c = decodeURIComponent(c); } catch { /* se queda tal cual */ }
    intentos.push(c);
    history.replaceState(null, "", location.pathname + location.search); // quita la clave de la barra
  }
  const guardada = leer(CLAVE_SECRETA, null);
  if (guardada) intentos.push(guardada);

  for (const c of intentos) {
    if (await intentarClave(c, meta)) {
      guardar(CLAVE_SECRETA, c);
      return;
    }
  }
  await pedirClave(meta);
}

// ---------- Calendario ----------
function crearGrid() {
  grid.innerHTML = "";
  const abiertas = leer(CLAVE, []);
  const h = hoy();
  const diaHoy = h.getFullYear() === CONFIG.anio && h.getMonth() === CONFIG.mes - 1 ? h.getDate() : null;

  for (const dia of orden()) {
    const especial = dia === CONFIG.dias;
    const p = document.createElement("div");
    p.className = "puerta";
    if (especial) p.classList.add("especial");
    if (abiertas.includes(dia)) p.classList.add("abierta");
    else if (desbloqueada(dia)) p.classList.add("disponible");
    else p.classList.add("bloqueada");

    p.innerHTML = `
      <div class="fondo"><span></span></div>
      <button class="hoja" aria-label="Puerta ${dia}"><span class="num"><b>${dia}</b></span></button>`;
    p.querySelector(".fondo span").textContent = ICONOS[dia] || "🎁";
    if (especial) p.querySelector(".hoja").insertAdjacentHTML("afterbegin", '<span class="lazo">🎀</span>');
    if (dia === diaHoy) p.insertAdjacentHTML("beforeend", '<span class="etiqueta">Hoy</span>');

    p.addEventListener("click", () => pulsar(dia, p));
    grid.appendChild(p);
  }
  actualizarProgreso();
}

function actualizarProgreso() {
  const n = leer(CLAVE, []).length;
  document.getElementById("progreso").textContent = `${n} de ${CONFIG.dias} puertas abiertas`;
}

function pulsar(dia, p) {
  if (!desbloqueada(dia)) {
    p.classList.remove("sacudida");
    void p.offsetWidth; // reinicia la animación
    p.classList.add("sacudida");
    toast(`Todavía no… esta se abre el ${dia} de ${MESES[CONFIG.mes - 1]} 😉`);
    return;
  }
  if (p.classList.contains("abierta")) {
    mostrar(dia);
    return;
  }
  p.classList.remove("disponible");
  p.classList.add("abierta");

  const abiertas = leer(CLAVE, []);
  if (!abiertas.includes(dia)) {
    abiertas.push(dia);
    guardar(CLAVE, abiertas);
  }
  actualizarProgreso();
  if (dia === CONFIG.dias) lanzarConfeti();
  setTimeout(() => mostrar(dia), 700);
}

// ---------- Visor ----------
let tokenVisor = 0;       // para ignorar cargas de una puerta que ya se ha cerrado
let urlsActuales = [];

function liberarUrls() {
  urlsActuales.forEach((u) => URL.revokeObjectURL(u));
  urlsActuales = [];
}

async function medio(m, token) {
  const claro = await descifrar(await descargar(`datos/m/${m.f}.bin`));
  if (token !== tokenVisor) return null;
  const url = URL.createObjectURL(new Blob([claro], { type: m.t }));
  urlsActuales.push(url);
  return url;
}

async function mostrar(dia) {
  const token = ++tokenVisor;
  liberarUrls();
  contenidoEl.innerHTML = "";

  el("p", { className: "fecha", textContent: `${dia} de ${MESES[CONFIG.mes - 1]}` });
  const titulo = el("h2", { textContent: "…" });

  visor.classList.add("visible");
  visor.setAttribute("aria-hidden", "false");
  visor.querySelector(".tarjeta").scrollTop = 0;

  let d;
  try {
    d = await descifrarJSON(`datos/d${dia}.bin`);
  } catch (e) {
    d = e.message === "HTTP 404"
      ? { titulo: "Sorpresa", texto: "Esta puerta aún se está preparando 🎁" }
      : { titulo: "Ups", texto: "No se ha podido abrir. Comprueba tu conexión y vuelve a tocar la puerta." };
  }
  if (token !== tokenVisor) return;

  titulo.textContent = d.titulo;
  if (d.texto) el("p", { textContent: d.texto });

  // Cada archivo multimedia se descarga y descifra aparte; mientras, sale "Cargando…"
  const colocar = (crear, m, padre = contenidoEl) => {
    const marca = el("p", { className: "cargando", textContent: "Cargando…" }, padre);
    medio(m, token)
      .then((url) => {
        if (url === null || token !== tokenVisor) return;
        marca.replaceWith(crear(url));
      })
      .catch(() => {
        if (token === tokenVisor) marca.textContent = "No se ha podido cargar este archivo.";
      });
  };

  const fotos = d.fotos || [];
  if (fotos.length === 1) {
    colocar((u) => nuevo("img", { src: u, alt: d.titulo }), fotos[0]);
  } else if (fotos.length > 1) {
    const g = el("div", { className: "galeria" });
    fotos.forEach((f) => colocar((u) => nuevo("img", { src: u, alt: d.titulo }), f, g));
  }
  if (d.audio) colocar((u) => nuevo("audio", { src: u, controls: true }), d.audio);
  if (d.video) colocar((u) => nuevo("video", { src: u, controls: true, playsInline: true }), d.video);

  if (d.enlace) {
    el("a", {
      href: d.enlace.url, target: "_blank", rel: "noopener",
      className: "boton", textContent: d.enlace.texto || "Abrir",
    });
  }
}

function cerrar() {
  tokenVisor++; // cancela cargas pendientes
  visor.classList.remove("visible");
  visor.setAttribute("aria-hidden", "true");
  contenidoEl.querySelectorAll("video, audio").forEach((m) => m.pause());
}

document.getElementById("cerrar").addEventListener("click", cerrar);
visor.addEventListener("click", (e) => { if (e.target === visor) cerrar(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") cerrar(); });

// ---------- Intro (sobre) ----------
const intro = document.getElementById("intro");
const sobre = document.getElementById("sobre");

function mostrarAvisoInstalar() {
  const yaEsApp = matchMedia("(display-mode: standalone)").matches || navigator.standalone;
  if (yaEsApp || leer(CLAVE_AVISO, false)) return;
  const aviso = document.getElementById("instalar");
  aviso.hidden = false;
  document.getElementById("instalar-cerrar").onclick = () => {
    aviso.hidden = true;
    guardar(CLAVE_AVISO, true);
  };
}

if (leer(CLAVE_INTRO, false) && !params.has("intro")) {
  intro.remove();
  mostrarAvisoInstalar();
} else {
  sobre.addEventListener("click", () => {
    sobre.querySelector(".sobre").classList.add("abierto");
    guardar(CLAVE_INTRO, true);
    setTimeout(() => {
      intro.classList.add("fuera");
      setTimeout(() => { intro.remove(); mostrarAvisoInstalar(); }, 900);
    }, 1700);
  }, { once: true });
}

// ---------- Nieve ----------
(function nieve() {
  if (CONFIG.tema === "claro" || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const c = document.getElementById("nieve");
  const ctx = c.getContext("2d");
  let w, h;
  const ajustar = () => { w = c.width = innerWidth; h = c.height = innerHeight; };
  ajustar();
  addEventListener("resize", ajustar);

  const copos = Array.from({ length: 60 }, () => ({
    x: Math.random() * innerWidth, y: Math.random() * innerHeight,
    r: Math.random() * 2.2 + 0.8, v: Math.random() * 0.6 + 0.3, d: Math.random() * Math.PI * 2,
  }));

  (function paso() {
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = "rgba(255,255,255,.8)";
    for (const f of copos) {
      f.y += f.v;
      f.d += 0.01;
      f.x += Math.sin(f.d) * 0.4;
      if (f.y > h) { f.y = -5; f.x = Math.random() * w; }
      ctx.beginPath();
      ctx.arc(f.x, f.y, f.r, 0, Math.PI * 2);
      ctx.fill();
    }
    requestAnimationFrame(paso);
  })();
})();

// ---------- Confeti ----------
function lanzarConfeti() {
  const c = document.getElementById("confeti");
  const ctx = c.getContext("2d");
  c.width = innerWidth;
  c.height = innerHeight;
  const colores = ["#f4c542", "#d0463b", "#2f8f68", "#ffffff", "#5aa9e6"];
  const trozos = Array.from({ length: 160 }, () => ({
    x: Math.random() * c.width, y: -20 - Math.random() * c.height * 0.4,
    w: 6 + Math.random() * 6, h: 8 + Math.random() * 8,
    vx: (Math.random() - 0.5) * 3, vy: 2 + Math.random() * 4,
    a: Math.random() * Math.PI, va: (Math.random() - 0.5) * 0.3,
    color: colores[Math.floor(Math.random() * colores.length)],
  }));
  const fin = performance.now() + 5000;

  (function paso(t) {
    ctx.clearRect(0, 0, c.width, c.height);
    for (const p of trozos) {
      p.x += p.vx; p.y += p.vy; p.vy += 0.04; p.a += p.va;
      ctx.save();
      ctx.translate(p.x, p.y);
      ctx.rotate(p.a);
      ctx.fillStyle = p.color;
      ctx.fillRect(-p.w / 2, -p.h / 2, p.w, p.h);
      ctx.restore();
    }
    if (t < fin) requestAnimationFrame(paso);
    else ctx.clearRect(0, 0, c.width, c.height);
  })(performance.now());
}

// ---------- Modo prueba (?prueba) ----------
if (params.has("prueba")) {
  document.body.classList.add("modo-prueba");
  document.getElementById("prueba").hidden = false;

  const fecha = document.getElementById("prueba-fecha");
  fecha.value = fechaPrueba || `${CONFIG.anio}-${String(CONFIG.mes).padStart(2, "0")}-01`;
  fechaPrueba = fecha.value;

  fecha.addEventListener("change", () => {
    fechaPrueba = fecha.value;
    crearGrid();
  });
  document.getElementById("prueba-reset").addEventListener("click", () => {
    try { localStorage.removeItem(CLAVE); } catch { /* nada */ }
    crearGrid();
  });
  document.getElementById("prueba-sobre").addEventListener("click", () => {
    try { localStorage.removeItem(CLAVE_INTRO); } catch { /* nada */ }
    location.reload();
  });
  document.getElementById("prueba-clave").addEventListener("click", () => {
    try { localStorage.removeItem(CLAVE_SECRETA); } catch { /* nada */ }
    location.reload();
  });
}

// ---------- Arranque ----------
function mostrarError(msg) {
  grid.innerHTML = "";
  const p = el("p", { className: "error-carga", textContent: msg }, grid);
  p.style.gridColumn = "1 / -1";
}

async function arrancar() {
  if (!window.crypto || !crypto.subtle) {
    mostrarError("Este navegador no puede abrir el calendario. Ábrelo desde Safari o Chrome, con la dirección https.");
    return;
  }
  try {
    await abrirCandado();
  } catch (e) {
    console.error(e);
    mostrarError("No se ha encontrado el contenido. ¿Has ejecutado privado/cifrar.py y subido la carpeta datos/?");
    return;
  }
  crearGrid();
}

arrancar();