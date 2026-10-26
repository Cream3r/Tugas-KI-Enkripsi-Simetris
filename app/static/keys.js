document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", async () => {
    const input = document.getElementById(button.dataset.copyTarget);
    if (!input) return;
    const originalText = button.textContent;
    const status = document.getElementById("key-copy-status");
    try {
      await navigator.clipboard.writeText(input.value);
      button.textContent = "Tersalin!";
      if (status) status.textContent = "Kunci berhasil disalin.";
      setTimeout(() => {
        button.textContent = originalText;
      }, 1500);
    } catch {
      input.focus();
      input.select();
      try {
        document.execCommand("copy");
        button.textContent = "Tersalin!";
        if (status) status.textContent = "Kunci berhasil disalin.";
        setTimeout(() => {
          button.textContent = originalText;
        }, 1500);
      } catch {
        button.textContent = "Pilih (Ctrl+C)";
        if (status) status.textContent = "Kunci sudah dipilih; tekan Ctrl+C untuk menyalin.";
        setTimeout(() => {
          button.textContent = originalText;
        }, 2000);
      }
    }
  });
});
