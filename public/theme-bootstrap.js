(() => {
  let theme = "light";
  try {
    theme = localStorage.getItem("clearbeacon-theme") === "dark" ? "dark" : "light";
  } catch (error) {
    console.warn("Could not read the saved display theme.", error);
  }
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]').content = theme === "dark" ? "#111110" : "#ECEBE1";
})();
