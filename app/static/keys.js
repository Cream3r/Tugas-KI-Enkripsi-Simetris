document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", async () => {
    const input = document.getElementById(button.dataset.copyTarget);
    const status = document.getElementById("key-copy-status");
    try {
      await navigator.clipboard.writeText(input.value);
      status.textContent = "Kunci berhasil disalin.";
    } catch {
      input.focus();
      input.select();
      status.textContent = "Penyalinan otomatis tidak tersedia. Kunci sudah dipilih; tekan Ctrl+C atau gunakan menu Salin.";
    }
  });
});
