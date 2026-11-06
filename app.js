"use strict";

const DB_NAME = "wds-private-vault";
const STORE_NAME = "vault";
const VAULT_KEY = "primary";
const FORMAT_VERSION = 1;
const KDF_ITERATIONS = 310000;
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const ui = {
  authScreen: document.querySelector("#auth-screen"),
  appShell: document.querySelector("#app-shell"),
  authForm: document.querySelector("#auth-form"),
  authTitle: document.querySelector("#auth-title"),
  authDescription: document.querySelector("#auth-description"),
  authSubmit: document.querySelector("#auth-submit"),
  authError: document.querySelector("#auth-error"),
  passphrase: document.querySelector("#passphrase"),
  confirmWrap: document.querySelector("#confirm-wrap"),
  confirmPassphrase: document.querySelector("#confirm-passphrase"),
  toggleAuthMode: document.querySelector("#toggle-auth-mode"),
  backupInput: document.querySelector("#backup-input"),
  navigation: document.querySelector("#navigation"),
  breadcrumb: document.querySelector("#breadcrumb-current"),
  overview: document.querySelector("#overview-view"),
  collection: document.querySelector("#collection-view"),
  collectionTitle: document.querySelector("#collection-title"),
  collectionEyebrow: document.querySelector("#collection-eyebrow"),
  collectionDescription: document.querySelector("#collection-description"),
  collectionList: document.querySelector("#collection-list"),
  collectionAdd: document.querySelector("#collection-add-button"),
  search: document.querySelector("#search-input"),
  resultCount: document.querySelector("#result-count"),
  entryDialog: document.querySelector("#entry-dialog"),
  entryForm: document.querySelector("#entry-form"),
  dialogTitle: document.querySelector("#dialog-title"),
  dialogEyebrow: document.querySelector("#dialog-eyebrow"),
  entryTitle: document.querySelector("#entry-title"),
  entryFile: document.querySelector("#entry-file"),
  entryTags: document.querySelector("#entry-tags"),
  entryError: document.querySelector("#entry-error"),
  toast: document.querySelector("#toast")
};

const categories = {
  documents: { type: "document", title: "Documents", eyebrow: "YOUR FILES", description: "Keep important files and the notes that go with them.", empty: "Your documents will feel right at home here.", icon: "▤" },
  emails: { type: "email", title: "Email archive", eyebrow: "CORRESPONDENCE", description: "Save the messages you’ll want to find again.", empty: "Keep the emails that matter, all in one place.", icon: "✉" },
  reports: { type: "report", title: "Report logs", eyebrow: "NOTES & REPORTS", description: "A private record of incidents, crashes, and other details.", empty: "A good place for the things worth keeping a record of.", icon: "◷" }
};

let database;
let cryptoKey;
let items = [];
let currentView = "overview";
let creatingVault = false;
let toastTimer;
let inactivityTimer;

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Could not open the local vault database."));
  });
}

function readEnvelope() {
  return new Promise((resolve, reject) => {
    const request = database.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(VAULT_KEY);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error || new Error("Could not read the local vault."));
  });
}

function writeEnvelope(envelope) {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).put(envelope, VAULT_KEY);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error || new Error("Could not save the encrypted vault."));
    transaction.onabort = () => reject(transaction.error || new Error("The vault save was cancelled."));
  });
}

function deleteEnvelope() {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).delete(VAULT_KEY);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error || new Error("Could not remove the local vault."));
  });
}

function toBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function fromBase64(value) {
  if (typeof value !== "string" || value.length > 200 * 1024 * 1024) throw new Error("The backup data is invalid or too large.");
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveKey(passphrase, salt, iterations) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function additionalData(salt) {
  return encoder.encode(`WDS|${FORMAT_VERSION}|${toBase64(salt)}`);
}

async function encryptItems(nextItems, key, salt) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify({ items: nextItems }));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: additionalData(salt) }, key, plaintext);
  return {
    format: FORMAT_VERSION,
    iterations: KDF_ITERATIONS,
    salt: toBase64(salt),
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(encrypted)),
    updatedAt: new Date().toISOString()
  };
}

function validateEnvelope(envelope) {
  return Boolean(envelope && envelope.format === FORMAT_VERSION &&
    Number.isInteger(envelope.iterations) && envelope.iterations >= KDF_ITERATIONS &&
    envelope.iterations <= 1000000 && typeof envelope.salt === "string" &&
    typeof envelope.iv === "string" && typeof envelope.ciphertext === "string");
}

async function decryptItems(envelope, passphrase) {
  if (!validateEnvelope(envelope)) throw new Error("This vault file is not a supported WDS backup.");
  const salt = fromBase64(envelope.salt);
  const iv = fromBase64(envelope.iv);
  if (salt.length !== 16 || iv.length !== 12) throw new Error("The vault data is invalid.");
  const key = await deriveKey(passphrase, salt, envelope.iterations);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: additionalData(salt) },
    key,
    fromBase64(envelope.ciphertext)
  );
  const parsed = JSON.parse(decoder.decode(plaintext));
  if (!parsed || !Array.isArray(parsed.items) || parsed.items.length > 10000) throw new Error("The vault data is invalid.");
  return { key, salt, items: parsed.items };
}

async function createVault(passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(passphrase, salt, KDF_ITERATIONS);
  const initialItems = [];
  await writeEnvelope(await encryptItems(initialItems, key, salt));
  cryptoKey = key;
  items = initialItems;
  showApp();
  showToast("Your encrypted vault is ready.");
}

async function unlockVault(passphrase) {
  const envelope = await readEnvelope();
  if (!envelope) throw new Error("No vault was found. Create a new vault or restore a backup.");
  const decrypted = await decryptItems(envelope, passphrase);
  cryptoKey = decrypted.key;
  items = decrypted.items;
  showApp();
}

async function saveItems(nextItems) {
  const envelope = await readEnvelope();
  if (!envelope || !cryptoKey) throw new Error("Your vault is locked. Unlock it before saving.");
  const salt = fromBase64(envelope.salt);
  const updatedEnvelope = await encryptItems(nextItems, cryptoKey, salt);
  await writeEnvelope(updatedEnvelope);
  items = nextItems;
  renderApp();
}

function showApp() {
  ui.authScreen.hidden = true;
  ui.appShell.hidden = false;
  ui.passphrase.value = "";
  ui.confirmPassphrase.value = "";
  currentView = "overview";
  renderApp();
  resetInactivityTimer();
}

function lockVault() {
  cryptoKey = undefined;
  items = [];
  clearTimeout(inactivityTimer);
  ui.appShell.hidden = true;
  ui.authScreen.hidden = false;
  ui.passphrase.value = "";
  ui.confirmPassphrase.value = "";
  ui.authError.textContent = "";
  updateAuthMode();
  ui.passphrase.focus();
}

function updateAuthMode() {
  const existing = Boolean(database && window.__wdsVaultExists);
  creatingVault = !existing;
  ui.confirmWrap.hidden = !creatingVault;
  ui.confirmPassphrase.required = creatingVault;
  ui.passphrase.autocomplete = creatingVault ? "new-password" : "current-password";
  ui.passphrase.minLength = creatingVault ? 12 : 1;
  ui.authTitle.innerHTML = creatingVault ? "A safer place<br>for what matters." : "Welcome back<br>to your vault.";
  ui.authDescription.textContent = creatingVault
    ? "Choose a strong passphrase. Your vault is encrypted on this device, and your passphrase cannot be recovered."
    : "Enter your passphrase to decrypt and open your private vault.";
  ui.authSubmit.innerHTML = creatingVault ? "Create encrypted vault <span aria-hidden=\"true\">→</span>" : "Unlock vault <span aria-hidden=\"true\">→</span>";
  ui.toggleAuthMode.textContent = creatingVault ? "" : "Create a new vault on this device";
  ui.toggleAuthMode.hidden = creatingVault;
}

function renderApp() {
  const counts = { document: 0, email: 0, report: 0 };
  for (const item of items) if (Object.hasOwn(counts, item.type)) counts[item.type] += 1;
  for (const [type, count] of Object.entries(counts)) {
    const navCount = document.querySelector(`[data-count="${type}"]`);
    if (navCount) navCount.textContent = String(count);
    const summaryCount = document.querySelector(`#${type}-count`);
    if (summaryCount) summaryCount.textContent = String(count);
  }
  const today = new Intl.DateTimeFormat(undefined, { weekday: "long", month: "long", day: "numeric" }).format(new Date());
  document.querySelector("#today-label").textContent = today;
  if (currentView === "overview") renderOverview();
  else renderCollection(currentView);
}

function renderOverview() {
  ui.overview.hidden = false;
  ui.collection.hidden = true;
  const recent = [...items].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 4);
  const container = document.querySelector("#recent-list");
  container.replaceChildren();
  if (!recent.length) {
    const empty = document.createElement("div");
    empty.className = "empty-recent";
    empty.textContent = "Your recent additions will appear here. Start by adding something to your vault.";
    container.append(empty);
    return;
  }
  for (const item of recent) {
    const row = document.createElement("div");
    row.className = "recent-row";
    const icon = document.createElement("span");
    icon.className = `recent-kind ${item.type === "email" ? "email" : item.type === "report" ? "report" : ""}`;
    icon.textContent = categories[item.type === "email" ? "emails" : item.type === "report" ? "reports" : "documents"].icon;
    const info = document.createElement("span");
    info.className = "recent-info";
    const title = document.createElement("strong");
    title.textContent = item.title;
    const subtitle = document.createElement("small");
    subtitle.textContent = `${categoryTitle(item.type)} · ${formatDate(item.createdAt)}`;
    info.append(title, subtitle);
    const date = document.createElement("span");
    date.className = "recent-date";
    date.textContent = formatRelativeDate(item.createdAt);
    row.append(icon, info, date);
    container.append(row);
  }
}

function renderCollection(view) {
  const config = categories[view];
  if (!config) return;
  ui.overview.hidden = true;
  ui.collection.hidden = false;
  ui.collectionEyebrow.textContent = config.eyebrow;
  ui.collectionTitle.textContent = config.title;
  ui.collectionDescription.textContent = config.description;
  ui.breadcrumb.textContent = config.title;
  const query = ui.search.value.trim().toLocaleLowerCase();
  const filtered = items.filter(item => item.type === config.type && searchableText(item).includes(query))
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  ui.resultCount.textContent = `${filtered.length} ${filtered.length === 1 ? "item" : "items"}`;
  ui.collectionList.replaceChildren();
  if (!filtered.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    const icon = document.createElement("span");
    icon.className = "empty-icon";
    icon.textContent = config.icon;
    const title = document.createElement("h3");
    title.textContent = query ? "Nothing found just yet." : config.empty;
    const message = document.createElement("p");
    message.textContent = query ? "Try another search term or clear your search." : "Only you can see what you add here.";
    empty.append(icon, title, message);
    if (!query) {
      const add = document.createElement("button");
      add.className = "button button-primary button-small";
      add.type = "button";
      add.textContent = `＋ Add ${config.type === "document" ? "a document" : config.type === "email" ? "an email" : "a report"}`;
      add.addEventListener("click", () => openEntryDialog(config.type));
      empty.append(add);
    }
    ui.collectionList.append(empty);
    return;
  }
  for (const item of filtered) ui.collectionList.append(createEntryCard(item));
}

function createEntryCard(item) {
  const card = document.createElement("article");
  card.className = "entry-card";
  const top = document.createElement("div");
  top.className = "entry-card-top";
  const titleWrap = document.createElement("div");
  titleWrap.className = "entry-card-title";
  const title = document.createElement("h3");
  title.textContent = item.title;
  const subtitle = document.createElement("small");
  subtitle.textContent = item.type === "email" && item.from
    ? `From ${item.from} · ${formatDate(item.date || item.createdAt)}`
    : item.type === "report" && item.category
      ? `${item.category} · ${formatDate(item.date || item.createdAt)}`
      : `Added ${formatDate(item.createdAt)}`;
  titleWrap.append(title, subtitle);
  const actions = document.createElement("div");
  actions.className = "entry-card-actions";
  if (item.attachment) {
    const download = document.createElement("button");
    download.type = "button";
    download.className = "entry-action";
    download.textContent = "↓ File";
    download.setAttribute("aria-label", `Download ${item.attachment.name}`);
    download.addEventListener("click", () => downloadAttachment(item));
    actions.append(download);
  }
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "entry-action danger";
  remove.textContent = "Delete";
  remove.addEventListener("click", () => deleteItem(item.id));
  actions.append(remove);
  top.append(titleWrap, actions);
  card.append(top);
  const descriptionText = item.type === "document" ? item.notes : item.body;
  if (descriptionText || item.to) {
    const description = document.createElement("p");
    description.className = "entry-description";
    description.textContent = item.type === "email" && item.to ? `To: ${item.to}${descriptionText ? ` · ${descriptionText}` : ""}` : (descriptionText || "");
    card.append(description);
  }
  const meta = document.createElement("div");
  meta.className = "entry-meta";
  if (item.attachment) {
    const file = document.createElement("span");
    file.className = "file-pill";
    file.textContent = `▧ ${item.attachment.name} · ${formatBytes(item.attachment.size)}`;
    meta.append(file);
  }
  for (const tagText of Array.isArray(item.tags) ? item.tags : []) {
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = tagText;
    meta.append(tag);
  }
  if (meta.childElementCount) card.append(meta);
  return card;
}

function searchableText(item) {
  return [item.title, item.notes, item.body, item.from, item.to, item.category, ...(Array.isArray(item.tags) ? item.tags : [])]
    .filter(value => typeof value === "string").join(" ").toLocaleLowerCase();
}

function categoryTitle(type) {
  if (type === "email") return "Email archive";
  if (type === "report") return "Report log";
  return "Document";
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Unknown date" : new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric" }).format(date);
}

function formatRelativeDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "";
  const days = Math.floor((Date.now() - date.valueOf()) / 86400000);
  if (days <= 0) return "Today";
  if (days === 1) return "Yesterday";
  if (days < 7) return `${days} days ago`;
  return formatDate(value);
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function safeFilename(name) {
  return name.replace(/[<>:"/\\|?*\u0000-\u001f]/g, "_").slice(0, 180) || "attachment";
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (typeof result !== "string") {
        reject(new Error("Could not read the selected file."));
        return;
      }
      resolve(result.slice(result.indexOf(",") + 1));
    };
    reader.onerror = () => reject(reader.error || new Error("Could not read the selected file."));
    reader.readAsDataURL(file);
  });
}

function downloadAttachment(item) {
  try {
    const bytes = fromBase64(item.attachment.data);
    const blob = new Blob([bytes], { type: item.attachment.type || "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = safeFilename(item.attachment.name);
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    showToast(`Could not download that attachment: ${error.message}`);
  }
}

function openEntryDialog(type) {
  ui.entryForm.reset();
  ui.entryError.textContent = "";
  for (const field of document.querySelectorAll(".category-fields")) field.hidden = true;
  const fields = document.querySelector(`#${type}-fields`);
  if (fields) fields.hidden = false;
  const title = type === "document" ? "Add a document" : type === "email" ? "Archive an email" : "Add a report log";
  ui.dialogTitle.textContent = title;
  ui.dialogEyebrow.textContent = `${type === "email" ? "EMAIL ARCHIVE" : type === "report" ? "REPORT LOG" : "DOCUMENT STORAGE"} · ENCRYPTED`;
  const dateInput = document.querySelector(`#${type === "email" ? "email-date" : "report-date"}`);
  if (dateInput) dateInput.value = new Date().toISOString().slice(0, 10);
  ui.entryDialog.dataset.type = type;
  ui.entryDialog.showModal();
  ui.entryTitle.focus();
}

async function addItem(event) {
  event.preventDefault();
  ui.entryError.textContent = "";
  const type = ui.entryDialog.dataset.type;
  const title = ui.entryTitle.value.trim();
  if (!title) {
    ui.entryError.textContent = "Please enter a title.";
    return;
  }
  const saveButton = document.querySelector("#entry-save");
  saveButton.disabled = true;
  saveButton.textContent = "Encrypting and saving…";
  try {
    const item = {
      id: crypto.randomUUID(),
      type,
      title,
      tags: ui.entryTags.value.split(",").map(tag => tag.trim()).filter(Boolean).slice(0, 20),
      createdAt: new Date().toISOString()
    };
    if (type === "document") {
      item.notes = document.querySelector("#document-notes").value.trim();
      const file = ui.entryFile.files[0];
      if (file) {
        if (file.size > MAX_FILE_BYTES) throw new Error("That file is over the 10 MB limit.");
        item.attachment = { name: safeFilename(file.name), type: file.type, size: file.size, data: await fileToBase64(file) };
      }
    } else if (type === "email") {
      item.from = document.querySelector("#email-from").value.trim();
      item.to = document.querySelector("#email-to").value.trim();
      item.date = document.querySelector("#email-date").value || item.createdAt;
      item.body = document.querySelector("#email-body").value.trim();
    } else {
      item.category = document.querySelector("#report-type").value;
      item.date = document.querySelector("#report-date").value || item.createdAt;
      item.body = document.querySelector("#report-body").value.trim();
    }
    await saveItems([...items, item]);
    ui.entryDialog.close();
    showToast("Saved securely to your vault.");
  } catch (error) {
    ui.entryError.textContent = error.message || "Could not save this item.";
  } finally {
    saveButton.disabled = false;
    saveButton.innerHTML = "Save securely <span>→</span>";
  }
}

async function deleteItem(id) {
  const item = items.find(entry => entry.id === id);
  if (!item || !window.confirm(`Permanently delete “${item.title}” from this vault?`)) return;
  try {
    await saveItems(items.filter(entry => entry.id !== id));
    showToast("Item deleted from your vault.");
  } catch (error) {
    showToast(`Could not delete the item: ${error.message}`);
  }
}

async function exportBackup() {
  try {
    const envelope = await readEnvelope();
    if (!envelope) throw new Error("There is no vault to back up.");
    const backup = { application: "WDS", ...envelope };
    const blob = new Blob([JSON.stringify(backup)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `wds-encrypted-backup-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast("Encrypted backup downloaded. Keep it somewhere safe.");
  } catch (error) {
    showToast(`Backup failed: ${error.message}`);
  }
}

async function importBackup(file) {
  ui.authError.textContent = "";
  try {
    if (file.size > 200 * 1024 * 1024) throw new Error("This backup file is too large.");
    const backup = JSON.parse(await file.text());
    if (backup.application !== "WDS" || !validateEnvelope(backup)) throw new Error("This is not a valid WDS encrypted backup.");
    const hasVault = await readEnvelope();
    if (hasVault && !window.confirm("Replace the vault currently saved in this browser? This cannot be undone.")) return;
    await writeEnvelope(backup);
    window.__wdsVaultExists = true;
    updateAuthMode();
    showToast("Backup restored. Unlock it with its original passphrase.");
  } catch (error) {
    ui.authError.textContent = `Could not restore this backup: ${error.message}`;
  } finally {
    ui.backupInput.value = "";
  }
}

function showToast(message) {
  ui.toast.textContent = message;
  ui.toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ui.toast.classList.remove("visible"), 3500);
}

function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  inactivityTimer = setTimeout(() => {
    if (!ui.appShell.hidden) {
      lockVault();
      showToast("Your vault was locked after 5 minutes of inactivity.");
    }
  }, 5 * 60 * 1000);
}

async function logClientError(title, details) {
  if (!cryptoKey || ui.appShell.hidden) return;
  const item = { id: crypto.randomUUID(), type: "report", category: "Crash", title, body: details.slice(0, 5000), date: new Date().toISOString().slice(0, 10), createdAt: new Date().toISOString(), tags: ["automatic", "crash-report"] };
  try {
    await saveItems([...items, item]);
  } catch {
    showToast("An automatic report could not be saved. Check that your browser has storage space.");
  }
}

async function initialize() {
  if (!window.isSecureContext || !crypto.subtle || !indexedDB) {
    ui.authError.textContent = "WDS needs a secure browser context with Web Crypto and IndexedDB. Open it through the local WDS server.";
    ui.authSubmit.disabled = true;
    return;
  }
  try {
    database = await openDatabase();
    window.__wdsVaultExists = Boolean(await readEnvelope());
    updateAuthMode();
  } catch (error) {
    ui.authError.textContent = `Could not initialize the local vault: ${error.message}`;
    ui.authSubmit.disabled = true;
  }
}

ui.authForm.addEventListener("submit", async event => {
  event.preventDefault();
  ui.authError.textContent = "";
  const passphrase = ui.passphrase.value;
  ui.authSubmit.disabled = true;
  try {
    if (creatingVault) {
      if (passphrase.length < 12) throw new Error("Choose a passphrase with at least 12 characters.");
      if (passphrase !== ui.confirmPassphrase.value) throw new Error("The passphrases do not match.");
      await createVault(passphrase);
      window.__wdsVaultExists = true;
      updateAuthMode();
    } else {
      await unlockVault(passphrase);
    }
  } catch {
    ui.authError.textContent = creatingVault
      ? "Could not create the vault. Check browser storage and try again."
      : "Could not unlock the vault. Check your passphrase or restore an encrypted backup.";
  } finally {
    ui.authSubmit.disabled = false;
  }
});

ui.toggleAuthMode.addEventListener("click", async () => {
  if (!window.confirm("This will permanently replace the vault saved in this browser. Download an encrypted backup first if you need the existing data. Continue?")) return;
  try {
    await deleteEnvelope();
    window.__wdsVaultExists = false;
    updateAuthMode();
    ui.passphrase.focus();
  } catch (error) {
    ui.authError.textContent = `Could not replace the vault: ${error.message}`;
  }
});

ui.backupInput.addEventListener("change", () => {
  const file = ui.backupInput.files[0];
  if (file) importBackup(file);
});
ui.navigation.addEventListener("click", event => {
  const button = event.target.closest("[data-view]");
  if (!button) return;
  currentView = button.dataset.view;
  for (const nav of ui.navigation.querySelectorAll(".nav-item")) nav.classList.toggle("active", nav === button);
  ui.breadcrumb.textContent = currentView === "overview" ? "Overview" : categories[currentView].title;
  ui.search.value = "";
  renderApp();
});
document.querySelectorAll("[data-go]").forEach(button => button.addEventListener("click", () => {
  currentView = button.dataset.go;
  for (const nav of ui.navigation.querySelectorAll(".nav-item")) nav.classList.toggle("active", nav.dataset.view === currentView);
  ui.breadcrumb.textContent = categories[currentView].title;
  ui.search.value = "";
  renderApp();
}));
ui.search.addEventListener("input", () => renderCollection(currentView));
ui.collectionAdd.addEventListener("click", () => openEntryDialog(categories[currentView].type));
document.querySelector("#header-add-button").addEventListener("click", () => openEntryDialog(currentView === "overview" ? "document" : categories[currentView].type));
document.querySelector("#backup-button").addEventListener("click", exportBackup);
document.querySelector("#lock-button").addEventListener("click", lockVault);
document.querySelector("#mobile-lock-button").addEventListener("click", lockVault);
ui.entryForm.addEventListener("submit", addItem);
document.querySelector("#dialog-close").addEventListener("click", () => ui.entryDialog.close());
document.querySelector("#dialog-cancel").addEventListener("click", () => ui.entryDialog.close());
for (const activity of ["pointerdown", "keydown", "input", "touchstart"]) {
  document.addEventListener(activity, () => { if (!ui.appShell.hidden) resetInactivityTimer(); }, { passive: true });
}
document.addEventListener("keydown", event => { if (event.key === "Escape" && ui.entryDialog.open) ui.entryDialog.close(); });
window.addEventListener("error", event => logClientError("Application error", event.message || "An unexpected application error occurred."));
window.addEventListener("unhandledrejection", event => logClientError("Unhandled application error", event.reason instanceof Error ? event.reason.message : "An unexpected asynchronous error occurred."));

initialize();
