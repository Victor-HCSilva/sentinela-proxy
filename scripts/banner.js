// ================================
// BANNER SUPERIOR
// ================================
if (!document.getElementById("sentinel-banner")) {

    const banner = document.createElement("div");

    banner.id = "sentinel-banner";

    banner.innerHTML = `
        <span>⚠ Tráfego monitorado pelo Sentinel</span>
        <button id="sentinel-banner-close">✕</button>
    `;

    Object.assign(banner.style, {
        position: "fixed",
        top: "0",
        left: "0",
        width: "100%",
        background: "#b71c1c",
        color: "white",
        zIndex: "999999",
        padding: "10px 15px",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        fontSize: "14px",
        fontFamily: "Arial",
        fontWeight: "bold",
        boxShadow: "0 2px 10px rgba(0,0,0,0.4)"
    });

    document.body.prepend(banner);

    // botão fechar
    const closeBtn = document.getElementById("sentinel-banner-close");

    Object.assign(closeBtn.style, {
        background: "transparent",
        border: "none",
        color: "white",
        fontSize: "18px",
        cursor: "pointer",
        fontWeight: "bold"
    });

    closeBtn.onclick = () => {
        banner.remove();
    };
}


// ================================
// BADGE LATERAL
// ================================
if (!document.getElementById("sentinel-badge")) {

    const badge = document.createElement("div");

    badge.id = "sentinel-badge";

    badge.innerHTML = `
        <div style="margin-bottom:8px;">
            MONITORADO
        </div>

        <button id="sentinel-badge-close">
            Fechar
        </button>
    `;

    Object.assign(badge.style, {
        position: "fixed",
        top: "55px",
        right: "10px",
        zIndex: "999999",
        background: "#c62828",
        color: "white",
        padding: "12px",
        borderRadius: "10px",
        fontWeight: "bold",
        fontFamily: "Arial",
        textAlign: "center",
        boxShadow: "0 0 15px rgba(0,0,0,0.35)",
        minWidth: "140px"
    });

    document.body.appendChild(badge);

    // botão fechar
    const closeBadge = document.getElementById("sentinel-badge-close");

    Object.assign(closeBadge.style, {
        marginTop: "5px",
        background: "white",
        color: "#c62828",
        border: "none",
        padding: "5px 10px",
        borderRadius: "5px",
        cursor: "pointer",
        fontWeight: "bold"
    });

    closeBadge.onclick = () => {
        badge.remove();
    };
}