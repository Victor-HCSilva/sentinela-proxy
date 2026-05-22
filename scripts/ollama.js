window.Sentinel = window.Sentinel || {};

window.Sentinel.askOllama = async function (content) {
    try {
        const response = await fetch("/sentinela-ollama/api/generate", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                model: "qwen2.5:3b",
                prompt: `
                    Faça um resumo do texto abaixo usando formatação Markdown
                    (.md). Use um título (##), crie uma lista de tópicos (-) 
                    e coloque os termos cruciais em **negrito**. 

                    ${content}
                    `,
                stream: false,
            }),
        });

        const data = await response.json();

        return data.response;
    } catch (err) {
        console.error(err);
        return "Erro ao comunicar com Ollama.";
    }
};
