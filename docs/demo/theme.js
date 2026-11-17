/* Runs before the page paints, so there is no flash: theme and favicon follow the saved choice, else the system's. */
(function () {
    var dark;
    try {
        var saved = localStorage.getItem("theme");
        dark = saved ? saved === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    } catch (e) { dark = true; }
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    var f = document.getElementById("favicon");
    if (f) f.href = dark ? "../favicon-dark.svg" : "../favicon-light.svg";
})();
