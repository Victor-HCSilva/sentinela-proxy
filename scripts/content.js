(() => {
    // Evita múltiplas injeções
    if (window.__sentinelInjected) return;
    window.__sentinelInjected = true;

    window.Sentinel = window.Sentinel || {};

    window.Sentinel.extractContent = function () { 
        try { 
            // O return TEM que estar na mesma linha ou agrupado
            return document.body.innerText.slice(0, 15000); 
        } catch (err) { 
            console.error(err);
            return ""; 
        } 
    };

    window.Sentinel.askOllama = async function (content) { 
        try { 
            // Usamos um caminho relativo que a proxy vai interceptar
            const response = await fetch("/sentinela-ollama/api/generate", { 
                method: "POST", 
                headers: { "Content-Type": "application/json" }, 
                body: JSON.stringify({ 
                    model: "qwen2.5:3b", 
                    prompt: `Faça um resumo do texto abaixo usando formatação Markdown (.md). Use um título (##), crie uma lista de tópicos (-) e coloque os termos cruciais em negrito.\n\n${content}`,
                    stream: false,
                }),
            });

            const data = await response.json();
            return data.response;
        } catch (err) {
            console.error("Erro no Ollama: ", err);
            return "Erro ao comunicar com Ollama. Verifique o console (F12) para erros de CORS ou conexão.";
        }
    };

    window.Sentinel.createPopup = function (text) { 
        const popup = document.createElement("div");

        popup.style.position = "fixed";
        popup.style.top = "20px";
        popup.style.right = "20px";
        popup.style.width = "400px";
        popup.style.height = "500px";
        popup.style.background = "white";
        popup.style.color = "black";
        popup.style.zIndex = "999999";
        popup.style.padding = "20px";
        popup.style.overflow = "auto";
        popup.style.border = "1px solid #ccc";
        popup.style.boxShadow = "0 4px 8px rgba(0,0,0,0.2)";
        // Para o Markdown não ficar em uma linha só:
        popup.style.whiteSpace = "pre-wrap"; 
        popup.style.fontFamily = "sans-serif";

        // Adiciona o texto e um botãozinho de fechar
        popup.innerHTML = `<button onclick="this.parentElement.remove()" style="float:right; cursor:pointer; color: red;">X</button><br>`;
        
        // Protege contra XSS e adiciona o texto do resumo
        const textNode = document.createTextNode(text);
        popup.appendChild(textNode);

        document.body.appendChild(popup);
    };

    function createButton() {
        const button = document.createElement("button");

        button.textContent = "Resumir";
        button.style.position = "fixed";
        button.style.bottom = "20px";
        button.style.right = "20px";
        button.style.zIndex = "999999";
        button.style.padding = "10px";
        button.style.background = "#007BFF";
        button.style.color = "white";
        button.style.border = "none";
        button.style.borderRadius = "5px";
        button.style.cursor = "pointer";

        button.addEventListener("click", async () => {
            button.disabled = true;
            button.textContent = "Resumindo...";

            const content = window.Sentinel.extractContent();
            const summary = await window.Sentinel.askOllama(content);

            window.Sentinel.createPopup(summary);

            button.disabled = false;
            button.textContent = "Resumir";
        });

        document.body.appendChild(button);
    }

    // ISSO É CRUCIAL: Aguarda a página carregar o body antes de criar o botão
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", createButton);
    } else {
        createButton();
    }
})();
