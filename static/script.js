
const scanForm = document.getElementById("scan-form");
const scanButton = document.getElementById("scan-button");
const urlInput = document.getElementById("url");
const scanAgainButton = document.getElementById("scan-again");

document.querySelectorAll(".example-chip").forEach((button) => {
  button.addEventListener("click", () => {
    urlInput.value = button.dataset.url || "";
    urlInput.focus();
    urlInput.scrollIntoView({ behavior: "smooth", block: "center" });
  });
});

if (scanForm && scanButton && urlInput) {
  scanForm.addEventListener("submit", (event) => {
    if (!urlInput.value.trim()) {
      event.preventDefault();
      urlInput.focus();
      return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning URL...";
  });
}

if (scanAgainButton && urlInput) {
  scanAgainButton.addEventListener("click", () => {
    urlInput.value = "";
    urlInput.focus();
    urlInput.scrollIntoView({ behavior: "smooth", block: "center" });
  });
}