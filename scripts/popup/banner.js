import { askOllama } from "../ollama/askOllama";

(() => {
    // =====================================================
    // PROTEÇÃO CONTRA DUPLA INJEÇÃO
    // =====================================================
    if (window.__sentinelInjected) {
        return;
    }

    window.__sentinelInjected = true;

    // =====================================================
    // CONFIG
    // =====================================================
    const BANNER_ID = "sentinela-banner";
    const BADGE_ID = "sentinel-badge";

    let bannerClosed = false;
    let badgeClosed = false;

    // =====================================================
    // HELPERS
    // =====================================================
    function safeStyle(element, styles) {
        try {
            Object.assign(element.style, styles);
        } catch (err) {
            console.error("[Sentinel] Style error:", err);
        }
    }

    function waitForBody(callback) {
        // body já existe
        if (document.body) {
            callback();
            return;
        }

        // DOM carregado
        document.addEventListener("DOMContentLoaded", callback, { once: true });

        // fallback
        window.addEventListener("load", callback, { once: true });
    }

    // =====================================================
    // BANNER SUPERIOR
    // =====================================================
    function createBanner() {
        // usuário fechou
        if (bannerClosed) {
            return;
        }

        // já existe
        if (document.getElementById(BANNER_ID)) {
            return;
        }

        try {
            const banner = document.createElement("div");

            banner.id = BANNER_ID;

            banner.setAttribute("data-sentinel", "banner");

            banner.innerHTML = `
                <span>
                    ⚠ Tráfego monitorado pelo Sentinel
                </span>

                <button
                    type="button"
                    id="sentinel-banner-close"
                    aria-label="Fechar banner"
                >
                    ✕
                </button>
            `;

            safeStyle(banner, {
                position: "fixed",
                top: "0",
                left: "0",
                width: "100%",
                background: "#b71c1c",
                color: "white",
                zIndex: "2147483647",
                padding: "10px 15px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                fontSize: "14px",
                fontFamily: "Arial, sans-serif",
                fontWeight: "bold",
                boxShadow: "0 2px 10px rgba(0,0,0,0.4)",
                boxSizing: "border-box",
            });

            document.body.prepend(banner);

            // busca local (robusto)
            const closeBtn = banner.querySelector("#sentinel-banner-close");

            if (closeBtn) {
                safeStyle(closeBtn, {
                    background: "transparent",
                    border: "none",
                    color: "white",
                    fontSize: "18px",
                    cursor: "pointer",
                    fontWeight: "bold",
                    marginLeft: "10px",
                    padding: "0",
                    lineHeight: "1",
                });

                // capture phase evita interferência de frameworks
                closeBtn.addEventListener(
                    "click",
                    (e) => {
                        e.preventDefault();
                        e.stopPropagation();

                        bannerClosed = true;

                        banner.remove();
                    },
                    true,
                );
            }
        } catch (err) {
            console.error("[Sentinel] Banner injection error:", err);
        }
    }

    // =====================================================
    // BADGE LATERAL
    // =====================================================
    function createBadge() {
        // usuário fechou
        if (badgeClosed) {
            return;
        }

        // já existe
        if (document.getElementById(BADGE_ID)) {
            return;
        }

        try {
            const badge = document.createElement("div");

            badge.id = BADGE_ID;

            badge.setAttribute("data-sentinel", "badge");

            badge.innerHTML = `
                <div style="margin-bottom:8px;">
                    MONITORADO
                </div>

                <button
                    type="button"
                    id="sentinel-badge-close"
                    aria-label="Fechar badge"
                >
                    Fechar
                </button>
            `;

            safeStyle(badge, {
                position: "fixed",
                top: "55px",
                right: "10px",
                zIndex: "2147483647",
                background: "#c62828",
                color: "white",
                padding: "12px",
                borderRadius: "10px",
                fontWeight: "bold",
                fontFamily: "Arial, sans-serif",
                textAlign: "center",
                boxShadow: "0 0 15px rgba(0,0,0,0.35)",
                minWidth: "140px",
                boxSizing: "border-box",
            });

            document.body.appendChild(badge);

            // busca local
            const closeBtn = badge.querySelector("#sentinel-badge-close");

            if (closeBtn) {
                safeStyle(closeBtn, {
                    marginTop: "5px",
                    background: "white",
                    color: "#c62828",
                    border: "none",
                    padding: "5px 10px",
                    borderRadius: "5px",
                    cursor: "pointer",
                    fontWeight: "bold",
                });

                closeBtn.addEventListener(
                    "click",
                    (e) => {
                        e.preventDefault();
                        e.stopPropagation();

                        badgeClosed = true;

                        badge.remove();
                    },
                    true,
                );
            }
        } catch (err) {
            console.error("[Sentinel] Badge injection error:", err);
        }
    }

    // =====================================================
    // INJEÇÃO PRINCIPAL
    // =====================================================
    function injectUI() {
        try {
            createBanner();
            createBadge();
        } catch (err) {
            console.error("[Sentinel] UI injection error:", err);
        }
    }

    // =====================================================
    // OBSERVER
    // =====================================================
    function startObserver() {
        try {
            const observer = new MutationObserver(() => {
                // evita recriar após fechamento
                if (!bannerClosed && !document.getElementById(BANNER_ID)) {
                    createBanner();
                }

                if (!badgeClosed && !document.getElementById(BADGE_ID)) {
                    createBadge();
                }
            });

            observer.observe(document.body, {
                childList: true,
                subtree: true,
            });
        } catch (err) {
            console.error("[Sentinel] Observer error:", err);
        }
    }

    // =====================================================
    // CRIA RESUMO DO CONTEÚDO
    // =====================================================
    function createSendToOllamaButton() {
        const button = document.createElement("button");

        button.textContent = "Send to Ollama";

        button.addEventListener("click", async () => {
            const resume = await askOllama();

            if (resume) {
                const resumeContent = createResumeContent(resume);

                document.body.appendChild(resumeContent);
            }
        });

        return button;
    }

    // =====================================================
    // EXECUÇÃO
    // =====================================================
    waitForBody(() => {
        // espera SPA/framework montar DOM
        setTimeout(() => {
            injectUI();
            startObserver();
            document.body.appendChild(createSendToOllamaButton());
        }, 300);
    });
})();
