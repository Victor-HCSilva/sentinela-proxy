window.Sentinel = window.Sentinel || {};

window.Sentinel.extractContent = function () {
    try {
        return document.body.innerText.slice(0, 15000);
    } catch (err) {
        console.error(err);
        return "";
    }
};
