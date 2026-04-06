document.addEventListener("DOMContentLoaded", () => {
    // ---------------------------
    // 1) Risk marker positioning
    // ---------------------------
    const track = document.querySelector(".dl-riskbar-track");
    const marker = document.querySelector(".dl-riskbar-marker");

    if (track && marker) {
        const raw = track.getAttribute("data-score");
        let score = Number(raw);
        if (!Number.isFinite(score)) score = 0;
        score = Math.max(0, Math.min(100, score));
        marker.style.left = score + "%";
    }

    // ---------------------------
    // 2) Tabs navigation
    // ---------------------------
    const links = Array.from(document.querySelectorAll(".dl-nav-link[data-tab]"));
    const panels = Array.from(document.querySelectorAll(".dl-tab[data-tab-panel]"));

    if (!links.length || !panels.length) return;

    function activate(tab) {
        // highlight menu
        links.forEach(a => {
            a.classList.toggle("dl-active", a.dataset.tab === tab);
        });

        // show panel
        panels.forEach(p => {
            p.classList.toggle("is-active", p.dataset.tabPanel === tab);
        });
    }

    // click handler (без перезагрузки)
    links.forEach(a => {
        a.addEventListener("click", (e) => {
            e.preventDefault();

            const tab = a.dataset.tab || "overview";

            // обновляем URL параметр tab, сохраняя url=...
            const u = new URL(window.location.href);
            u.searchParams.set("tab", tab);
            history.replaceState(null, "", u.toString());

            activate(tab);
        });
    });

    // init from URL (?tab=...)
    const initTab = new URL(window.location.href).searchParams.get("tab") || "overview";
    activate(initTab);
});
