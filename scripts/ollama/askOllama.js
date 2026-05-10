import { loadContent } from "../content/loadContent";

const defaultPrompt = "Resuma este conteúdo:";
const defaultModel = "deepseek-r1:14b";

async function askOllama() {
    const content = loadContent();

    const response = await fetch("http://127.0.0.1:11434/api/generate", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            model: defaultModel,
            prompt: `${defaultPrompt}\n${content}`,
            stream: false,
        }),
    });

    const data = await response.json();

    return data.response;
}

export { askOllama };
