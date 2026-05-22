window.Sentinel = window.Sentinel || {};
window.Sentinel.showBanner = function (summary) {
    const newWindow = window.open();
    if (!newWindow) {
        console.error("Popup bloqueado pelo navegador. Por favor, permita popups para este site.");
        return;
    }
    newWindow.document.write(`
        <html>
            <head><title>Resumo</title></head>
            <body style="font-family: sans-serif; padding: 20px;">
                <h2>Resumo da Página</h2>
                <pre style="white-space: pre-wrap;">${summary}</pre>
                <button onclick="window.close()">Fechar</button>
            </body>
        </html>
    `);
};
