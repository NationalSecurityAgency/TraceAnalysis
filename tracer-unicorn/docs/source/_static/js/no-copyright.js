document.addEventListener("DOMContentLoaded", function() {
    let footer = document.getElementsByClassName("footer")[0];
    let inner = footer.getInnerHTML();
    footer.innerHTML = inner.substr(inner.indexOf("Powered"));
});
