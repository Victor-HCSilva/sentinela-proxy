window.Sentinel = window.Sentinel || {};

window.Sentinel.createPopup = function (text) {
    const popup = document.createElement("div");

    popup.style.position = "fixed";
    popup.style.top = "20px";
    popup.style.right = "20px";
    popup.style.width = "400px";
    popup.style.height = "500px";
    popup.style.background = "white";
    popup.style.zIndex = "999999";
    popup.style.padding = "20px";
    popup.style.overflow = "auto";
    popup.style.border = "1px solid #ccc";

    popup.textContent = text;

    document.body.appendChild(popup);
};
