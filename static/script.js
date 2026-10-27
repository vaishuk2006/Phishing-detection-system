
document.addEventListener("DOMContentLoaded", function () {
    const urlInput = document.getElementById("url");

    if (urlInput) {
        urlInput.addEventListener("input", function () {
            urlInput.setCustomValidity("");
        });
    }

    document.querySelectorAll("form").forEach(function (form) {
        form.addEventListener("submit", function () {
            const button = form.querySelector('button[type="submit"]');

            if (button && form.checkValidity()) {
                button.disabled = true;
                button.textContent = "Analyzing...";
            }
        });
    });
});
