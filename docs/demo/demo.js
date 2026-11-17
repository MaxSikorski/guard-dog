/* Plays the events the real Rust code produced (compiled to WebAssembly) slowly, so you can read along.
   All text goes in with textContent, never innerHTML: the page is as careful as the code it shows. */
(function () {
    "use strict";
    var $ = function (id) { return document.getElementById(id); };
    var runBtn = $("run"), skipBtn = $("skip"), log = $("log"), cards = $("cards");
    var reduced = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
    var hasGsap = typeof gsap !== "undefined";
    var wasmBytes = 0, engineMs = 0, events = null, sceneCount = 0;
    var timer = null, queue = [], cardFor = {}, current = null;

    /* ---------- Theme toggle ---------- */
    (function () {
        var sun = "M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z";
        var moon = "M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z";
        var btn = $("theme-toggle"), icon = $("theme-icon");
        function apply(dark, animate) {
            document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
            try { localStorage.setItem("theme", dark ? "dark" : "light"); } catch (e) {}
            var meta = document.querySelector('meta[name="theme-color"]');
            if (meta) meta.content = dark ? "#000000" : "#f5f5f7";
            icon.querySelector("path").setAttribute("d", dark ? sun : moon);
            var f = $("favicon");
            if (f) f.href = dark ? "../favicon-dark.svg" : "../favicon-light.svg";
            if (animate && hasGsap && !reduced) gsap.fromTo(icon, { rotation: 0, scale: 0.8 }, { rotation: 360, scale: 1, duration: 0.6, ease: "power2.out" });
        }
        var isDark = document.documentElement.getAttribute("data-theme") !== "light";
        apply(isDark, false);
        btn.addEventListener("click", function () { isDark = !isDark; apply(isDark, true); });
    })();

    /* ---------- The engine: Rust compiled to WebAssembly ---------- */
    function decodeBase64(b64) {
        var bin = atob(b64), bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
    }

    async function loadEngine() {
        if (typeof window.GD_WASM_BASE64 !== "string") throw new Error("the engine file (watchdog.wasm.js) did not load");
        var bytes = decodeBase64(window.GD_WASM_BASE64);
        wasmBytes = bytes.byteLength;
        var inst = await WebAssembly.instantiate(bytes, {});
        var ex = inst.instance.exports;
        var t0 = performance.now();
        var ptr = ex.demo_run(), len = ex.demo_len();
        var text = new TextDecoder("utf-8").decode(new Uint8Array(ex.memory.buffer, ptr, len));
        engineMs = performance.now() - t0;
        return JSON.parse(text);
    }

    /* ---------- Drawing ---------- */
    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text !== undefined) e.textContent = text;
        return e;
    }
    function addLine(cls, text) {
        var d = el("div", "line " + cls, text);
        log.appendChild(d);
        if (hasGsap && !reduced) gsap.from(d, { opacity: 0, y: 6, duration: 0.3 });
        return d;
    }
    function setCard(n, state, label) {
        var c = cardFor[n];
        if (!c) return;
        c.card.className = "card scene-card " + state;
        c.state.textContent = label;
    }

    function play(e) {
        switch (e.t) {
            case "scene":
                current = e.n;
                $("scene-label").textContent = "Scene " + e.n + " of " + sceneCount;
                $("scene-title").textContent = e.title;
                $("scene-story").textContent = e.story;
                setCard(e.n, "live", "Checking…");
                addLine("head", "Scene " + e.n + ": " + e.title);
                break;
            case "step": addLine("", e.text); break;
            case "show":
                addLine("", e.label + ":");
                addLine("quote", "| " + e.text);
                break;
            case "good": addLine("", "ok. " + e.text); break;
            case "caught":
                addLine("caught", "Caught. " + e.text);
                setCard(current, "caught", "Caught");
                break;
            case "missed":
                addLine("missed", "MISSED. " + e.text + " This is a bug; please report it.");
                setCard(current, "missed", "NOT CAUGHT");
                break;
            case "todo": break; /* shown in its own list at the end */
        }
    }

    function finish() {
        var caught = 0, missed = 0, todos = [];
        var ok;
        events.forEach(function (e) {
            if (e.t === "caught") caught++;
            else if (e.t === "missed") missed++;
            else if (e.t === "todo") todos.push(e);
        });
        $("scene-label").textContent = "Done";
        $("result").classList.remove("hidden");
        ok = missed === 0 && caught === sceneCount && sceneCount > 0;
        var title = $("result-title");
        title.textContent = ok
            ? caught + " of " + sceneCount + " planted cases caught."
            : "FAILED: " + caught + " of " + sceneCount + " planted cases caught, " + missed + " not caught.";
        title.className = "result-title" + (ok ? "" : " fail");
        $("result-proof").textContent = "Run by the real Guard Dog Rust code, compiled to WebAssembly (" +
            Math.round(wasmBytes / 1024) + " KB), in " + Math.max(1, Math.round(engineMs)) + " ms. This page just replays it slowly.";
        if (todos.length) {
            var ul = $("todo-list");
            ul.textContent = "";
            todos.forEach(function (t) { ul.appendChild(el("li", "", t.title + " (arrives with " + t.arrives_with + ")")); });
            $("todo-block").classList.remove("hidden");
        }
        skipBtn.classList.add("hidden");
        runBtn.disabled = false;
        runBtn.textContent = "Run it again";
    }

    function step() {
        if (!queue.length) { timer = null; finish(); return; }
        play(queue.shift());
        timer = setTimeout(step, reduced ? 0 : 700);
    }

    function start() {
        if (timer) clearTimeout(timer);
        log.textContent = "";
        $("result").classList.add("hidden");
        cards.textContent = "";
        cardFor = {};
        events.forEach(function (e) {
            if (e.t !== "scene") return;
            var card = el("div", "card scene-card"), state = el("div", "state", "Waiting");
            card.appendChild(el("div", "card-title", "Scene " + e.n));
            card.appendChild(el("div", "card-desc", e.title));
            card.appendChild(state);
            cards.appendChild(card);
            cardFor[e.n] = { card: card, state: state };
        });
        sceneCount = events.filter(function (e) { return e.t === "scene"; }).length;
        queue = events.slice();
        runBtn.disabled = true;
        runBtn.textContent = "Running…";
        skipBtn.classList.remove("hidden");
        step();
    }

    skipBtn.addEventListener("click", function () {
        if (timer) clearTimeout(timer);
        while (queue.length) play(queue.shift());
        timer = null;
        finish();
    });
    runBtn.addEventListener("click", start);

    loadEngine().then(function (ev) {
        events = ev;
        runBtn.disabled = false;
        runBtn.textContent = "Run the demo";
    }).catch(function (err) {
        runBtn.textContent = "Could not load the engine";
        addLine("missed", String(err && err.message ? err.message : err));
    });
})();
