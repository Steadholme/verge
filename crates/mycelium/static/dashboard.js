(() => {
  const card = document.getElementById("vpn-profile-card");
  if (!card) return;
  fetch("/api/clash/capability", {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
    .then((response) => {
      if (response.status === 204) card.hidden = false;
    })
    .catch(() => {});
})();
