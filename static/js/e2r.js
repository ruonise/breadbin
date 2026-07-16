window.togglePasteContent = () => {
  const contentDiv = document.querySelector(".paste-content");

  if (typeof window.showingHTMLOnly === "undefined") {
    window.showingHTMLOnly = false;
  }

  if (!window.showingHTMLOnly) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(window.pasteContentJSON, "text/html");

    doc
      .querySelectorAll("[style]")
      .forEach((el) => el.removeAttribute("style"));

    doc.querySelectorAll("style").forEach((styleEl) => styleEl.remove());

    const htmlContent = doc.body.innerHTML;

    contentDiv.innerHTML = htmlContent;
    window.showingHTMLOnly = true;
  } else {
    contentDiv.innerHTML = window.originalContent || "";
    window.showingHTMLOnly = false;
  }
};

document.addEventListener("DOMContentLoaded", () => {
  const contentElement = document.querySelector(".paste-content");
  if (contentElement) {
    window.originalContent = contentElement.innerHTML;
  }

  const toggleBtn = document.getElementById("toggleButton");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      window.togglePasteContent();
    });
  }
});
