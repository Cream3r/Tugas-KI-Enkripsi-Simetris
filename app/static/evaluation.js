const form = document.getElementById("evaluation-form");
if (form) {
  const source = document.getElementById("source");
  const sample = document.getElementById("sample-size");
  const file = document.getElementById("test-file");
  const status = document.getElementById("evaluation-progress");
  const sync = () => {
    const uploading = source.value === "upload";
    file.disabled = !uploading;
    file.required = uploading;
    sample.disabled = uploading;
  };
  source.addEventListener("change", sync);
  sync();
  form.addEventListener("submit", (event) => {
    status.textContent = "Pengujian berjalan. Tunggu hingga hasil tampil atau laporan JSON selesai diunduh.";
    // Download responses leave the current page open; keep controls usable afterward.
  });
}
