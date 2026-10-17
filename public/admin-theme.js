(() => {
  const button = document.getElementById("theme-toggle");
  const root = document.documentElement;
  const themeColor = document.querySelector('meta[name="theme-color"]');

  if (!button || !themeColor) {
    throw new Error("The admin theme controls are missing.");
  }

  const render = (theme) => {
    const dark = theme === "dark";
    root.dataset.theme = dark ? "dark" : "light";
    themeColor.content = dark ? "#111110" : "#ECEBE1";
    button.setAttribute("aria-label", dark ? "Switch to day mode" : "Switch to night mode");
    button.setAttribute("aria-pressed", String(dark));
    button.firstElementChild.textContent = dark ? "☀" : "☾";
  };

  render(root.dataset.theme);

  button.addEventListener("click", () => {
    const theme = root.dataset.theme === "dark" ? "light" : "dark";
    render(theme);
    try {
      localStorage.setItem("clearbeacon-theme", theme);
    } catch (error) {
      console.warn("Could not save the display theme.", error);
    }
  });

  window.addEventListener("storage", (event) => {
    if (event.key === "clearbeacon-theme") {
      render(event.newValue === "dark" ? "dark" : "light");
    }
  });

  const sidebar = document.getElementById("admin-sidebar");
  const sidebarToggle = document.getElementById("sidebar-toggle");
  if (!sidebar || !sidebarToggle) {
    throw new Error("The reviewer navigation controls are missing.");
  }

  const closeSidebar = () => {
    sidebar.classList.remove("is-open");
    document.body.classList.remove("admin-sidebar-open");
    sidebarToggle.setAttribute("aria-expanded", "false");
    sidebarToggle.setAttribute("aria-label", "Open reviewer navigation");
  };

  sidebarToggle.addEventListener("click", () => {
    if (window.matchMedia("(max-width: 900px)").matches) {
      const isOpen = sidebar.classList.toggle("is-open");
      document.body.classList.toggle("admin-sidebar-open", isOpen);
      sidebarToggle.setAttribute("aria-expanded", String(isOpen));
      sidebarToggle.setAttribute("aria-label", isOpen ? "Close reviewer navigation" : "Open reviewer navigation");
    } else {
      document.body.classList.toggle("admin-sidebar-collapsed");
      sidebarToggle.setAttribute("aria-expanded", String(!document.body.classList.contains("admin-sidebar-collapsed")));
      sidebarToggle.setAttribute("aria-label", document.body.classList.contains("admin-sidebar-collapsed") ? "Open reviewer navigation" : "Close reviewer navigation");
    }
  });

  sidebar.addEventListener("click", (event) => {
    const link = event.target.closest(".sidebar-link");
    if (!link) return;
    for (const item of sidebar.querySelectorAll(".sidebar-link")) {
      item.classList.toggle("active", item === link);
    }
    closeSidebar();
  });

  document.addEventListener("click", (event) => {
    if (document.body.classList.contains("admin-sidebar-open") && !sidebar.contains(event.target) && !sidebarToggle.contains(event.target)) {
      closeSidebar();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeSidebar();
  });
})();
