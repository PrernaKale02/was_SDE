document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-fill-sample]").forEach((button) => {
    button.addEventListener("click", () => {
      const form = button.closest(".test-panel")?.querySelector(".login-form");
      const username = form?.querySelector('[name="username"]');
      const password = form?.querySelector('[name="password"]');
      if (!username || !password) return;
      username.value = button.dataset.username || "student";
      password.value = button.dataset.password || "LabPass123!";
      username.focus();
    });
  });

  document.querySelectorAll(".login-form").forEach((form) => {
    form.addEventListener("submit", () => {
      const button = form.querySelector('button[type="submit"]');
      if (!button) return;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      button.textContent = "Checking credentials…";
    });
  });
});
