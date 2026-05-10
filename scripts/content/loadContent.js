import { Readability } from "@mozilla/readability";

function loadContent() {
    try {
        const MAX_CHARS = 15000;

        const cloned = document.cloneNode(true);

        const article = new Readability(cloned).parse();

        const cleanText = article?.textContent || "";

        return cleanText.slice(0, MAX_CHARS);
    } catch (error) {
        console.error(error);
        return "";
    }
}

export { loadContent };
